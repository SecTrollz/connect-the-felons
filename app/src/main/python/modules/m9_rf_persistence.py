#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 9 - RF Surveillance Detection & Persistence Forensics

Two jobs, one module:

  1. RF DETECTION - look for radio-frequency indicators of nearby
     surveillance hardware: rogue / evil-twin Wi-Fi access points,
     IMSI-catcher (Stingray) heuristics on the cellular radio, a
     magnetic-field sweep that can flag hidden bugs/cameras, and -
     if a USB RTL-SDR dongle is attached - a real wideband spectrum
     sweep instead of metadata heuristics.

  2. PERSISTENCE DETECTION - look for the classic Android
     stalkerware/RAT footholds on YOUR OWN device: abused
     Accessibility Service grants, Device Admin, boot-completed
     receivers, SYSTEM_ALERT_WINDOW overlays, sideloaded APKs hidden
     from the launcher, and known stalkerware package signatures.

Data sources (all local or direct-to-device, no subscriptions):
  - termux-api commands: termux-wifi-scaninfo, termux-telephony-cellinfo,
    termux-sensor. Require `pkg install termux-api` plus the Termux:API
    companion app from F-Droid/Play. Run directly on-device.
  - ADB shell: own device only, over USB debugging - same convention
    Module 5 uses for adb_device_info().
  - rtl_power (optional): `pkg install rtl-sdr` + a USB-OTG RTL-SDR
    dongle, for a genuine RF power sweep across an ISM band.
  - Local stalkerware signature file:
    ctf/data/stalkerware/signatures.json - ships empty, same pattern as
    Module 5's OUI/TAC databases. Populate it from a vetted IOC feed
    (Amnesty International's Mobile Verification Toolkit indicators,
    the Coalition Against Stalkerware threat list) - this module does
    not ship fabricated "known spyware" package names, because a wrong
    guess there is worse than an empty database.

LEGAL/ETHICAL NOTE: the persistence checks in this module audit YOUR
OWN device or a device you have explicit authorization to examine.
Running them against someone else's device without consent is
unlawful in most jurisdictions. The RF checks are passive (receive
only) - nothing in this module transmits.
"""

import subprocess
import json
import os
import re
import sys
import shutil
import statistics
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal

DATA_DIR = Path(__file__).parent.parent / "data"


# ─────────────────────────────────────────────────────────────────────
# SHELL EXECUTION - local Termux shell or ADB (own device only)
# ─────────────────────────────────────────────────────────────────────

def _find_adb():
    """Same search order as Module 5's adb_device_info()."""
    candidates = [
        "adb",
        os.path.expanduser("~/bin/adb"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "adb"),
    ]
    for path in candidates:
        try:
            subprocess.run([path, "version"], capture_output=True, timeout=5)
            return path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


class DeviceShell:
    """
    Runs commands either directly (when this code is executing inside
    Termux on the phone being audited - the case for termux-api and
    rtl_power binaries) or via `adb shell` (when auditing a separate
    device over USB debugging, or when a command needs shell-level
    package visibility that Termux's own app sandbox doesn't have).

    Tries local execution first, ADB second, unless told otherwise.
    Reports which path actually answered so results can note their
    provenance.
    """

    def __init__(self):
        self.adb_bin = _find_adb()
        self.adb_connected = False
        if self.adb_bin:
            try:
                devices = subprocess.run(
                    [self.adb_bin, "devices"], capture_output=True, text=True, timeout=10
                )
                lines = [l for l in devices.stdout.splitlines()[1:] if l.strip()]
                self.adb_connected = any(l.endswith("device") for l in lines)
            except Exception:
                pass

    def has_local_binary(self, name):
        return shutil.which(name) is not None

    def run(self, args, timeout=15, prefer="local"):
        """
        args: list like ["pm", "list", "packages", "-f"]
        Returns (stdout_str_or_None, mode_used_or_None).
        """
        order = ["local", "adb"] if prefer == "local" else ["adb", "local"]
        for mode in order:
            if mode == "local" and shutil.which(args[0]):
                try:
                    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
                    return proc.stdout, "local"
                except Exception:
                    continue
            if mode == "adb" and self.adb_connected:
                try:
                    proc = subprocess.run(
                        [self.adb_bin, "shell"] + args, capture_output=True, text=True, timeout=timeout
                    )
                    return proc.stdout, "adb"
                except Exception:
                    continue
        return None, None


# ─────────────────────────────────────────────────────────────────────
# RF DETECTION - WI-FI (rogue / evil-twin access point heuristics)
# ─────────────────────────────────────────────────────────────────────

def wifi_scan(shell):
    """
    termux-wifi-scaninfo returns a JSON array of nearby APs:
    [{"bssid": "...", "ssid": "...", "frequency": 2437, "level": -47,
      "capabilities": "[WPA2-PSK-CCMP][ESS]", ...}, ...]
    """
    out, mode = shell.run(["termux-wifi-scaninfo"], timeout=20)
    if not out:
        return {"available": False, "error": "termux-wifi-scaninfo unavailable "
                "(pkg install termux-api + Termux:API companion app, grant location permission)"}
    try:
        aps = json.loads(out)
    except json.JSONDecodeError:
        return {"available": False, "error": "Could not parse termux-wifi-scaninfo output"}
    return {"available": True, "mode": mode, "access_points": aps}


def analyze_wifi_scan(scan):
    """
    Rogue / evil-twin AP heuristics on a single scan snapshot:
      - Same SSID broadcast by 2+ BSSIDs with different first-3-octet
        OUI vendor = classic evil-twin setup (a legitimate multi-AP
        network normally shares one vendor across all its APs).
      - Hidden (empty) SSID sitting at unusually strong signal
        (>= -50 dBm, i.e. within a few meters) = consistent with a
        planted AP/pineapple close to the device rather than a
        building's normal infrastructure.
    This is metadata analysis, not proof - it flags what's worth a
    second look.
    """
    flags = []
    aps = scan.get("access_points", []) or []
    if not aps:
        return {"flags": flags, "ap_count": 0}

    by_ssid = {}
    for ap in aps:
        ssid = ap.get("ssid", "")
        by_ssid.setdefault(ssid, []).append(ap)

    for ssid, group in by_ssid.items():
        if not ssid:
            continue
        ouis = {ap.get("bssid", "")[:8].upper() for ap in group if ap.get("bssid")}
        if len(group) > 1 and len(ouis) > 1:
            flags.append({
                "type": "POSSIBLE_EVIL_TWIN",
                "ssid": ssid,
                "bssids": [ap.get("bssid") for ap in group],
                "reason": f"SSID '{ssid}' broadcast by {len(group)} access points from "
                          f"{len(ouis)} different hardware vendors",
            })

    for ap in aps:
        if not ap.get("ssid") and ap.get("level", -100) >= -50:
            flags.append({
                "type": "STRONG_HIDDEN_SSID",
                "bssid": ap.get("bssid"),
                "level_dbm": ap.get("level"),
                "reason": "Hidden-SSID access point at very close range (>= -50 dBm)",
            })

    return {"flags": flags, "ap_count": len(aps)}


# ─────────────────────────────────────────────────────────────────────
# RF DETECTION - CELLULAR (IMSI-catcher / Stingray heuristics)
# ─────────────────────────────────────────────────────────────────────

def cellular_scan(shell):
    """termux-telephony-cellinfo returns a JSON array of visible cell towers."""
    out, mode = shell.run(["termux-telephony-cellinfo"], timeout=20)
    if not out:
        return {"available": False, "error": "termux-telephony-cellinfo unavailable "
                "(pkg install termux-api + Termux:API companion app, grant phone permission)"}
    try:
        cells = json.loads(out)
    except json.JSONDecodeError:
        return {"available": False, "error": "Could not parse termux-telephony-cellinfo output"}
    return {"available": True, "mode": mode, "cells": cells}


def analyze_cellular_scan(scan):
    """
    IMSI-catcher heuristics on a single cellular snapshot:
      - Forced downgrade to 2G (GSM/EDGE) when no LTE/5G cell is visible
        at all is the single most common Stingray tell - fake base
        stations frequently only speak 2G because that's where
        encryption/authentication is weakest or absent.
      - Suspiciously few neighbor cells: a real tower location usually
        has multiple neighbor cells visible; a single isolated strong
        cell with no neighbors can indicate a nearby rogue base station
        deliberately out-shouting the real network.
    None of this is proof by itself - it is exactly the kind of signal
    that turns into a formal request for carrier tower records.
    """
    flags = []
    cells = scan.get("cells", []) or []
    if not cells:
        return {"flags": flags, "cell_count": 0}

    downgrade_types = {"gsm", "edge", "2g"}
    registered = [c for c in cells if c.get("registered")]
    types_seen = {str(c.get("type", "")).lower() for c in cells}

    if registered:
        reg_types = {str(c.get("type", "")).lower() for c in registered}
        if reg_types & downgrade_types and not (types_seen - downgrade_types):
            flags.append({
                "type": "POSSIBLE_2G_DOWNGRADE",
                "reason": "Registered cell is 2G (GSM/EDGE) with no LTE/5G cells visible at all - "
                          "consistent with an IMSI-catcher forcing a downgrade",
            })

    if len(cells) == 1 and registered:
        flags.append({
            "type": "ISOLATED_CELL",
            "reason": "Only one cell tower visible, no neighbor cells - unusual outside "
                      "very rural areas, consistent with signal being dominated by a "
                      "single nearby rogue base station",
        })

    strengths = [c.get("dbm") for c in cells if isinstance(c.get("dbm"), (int, float))]
    if strengths and max(strengths) > -60 and len(cells) <= 2:
        flags.append({
            "type": "ANOMALOUS_SIGNAL_STRENGTH",
            "max_dbm": max(strengths),
            "reason": "Very strong signal (>-60 dBm) from very few towers - consistent "
                      "with a base station much closer than a normal cell site",
        })

    return {"flags": flags, "cell_count": len(cells), "types_seen": sorted(types_seen)}


# ─────────────────────────────────────────────────────────────────────
# RF DETECTION - MAGNETIC FIELD SWEEP (physical bug/camera sweep aid)
# ─────────────────────────────────────────────────────────────────────

def magnetic_field_sweep(shell, samples=8):
    """
    termux-sensor -s "Magnetic Field" -n N samples the phone's
    magnetometer. Hidden cameras, microphones, and GPS trackers almost
    always contain a small motor, coil, or battery that perturbs the
    local magnetic field - the same principle a commercial RF/bug
    detector uses in its magnetic mode. Walking the phone slowly
    across a suspect area and watching for a spike well above the
    ambient baseline is a well-known DIY sweep technique.

    This function takes a short stationary reading and reports the raw
    values plus the spread - the actual sweep (physically moving the
    phone around a room) is something the investigator does, this just
    gives them the numbers to watch while they do it.
    """
    out, mode = shell.run(
        ["termux-sensor", "-s", "Magnetic Field", "-n", str(samples)], timeout=max(15, samples * 2)
    )
    if not out:
        return {"available": False, "error": "termux-sensor unavailable "
                "(pkg install termux-api + Termux:API companion app)"}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"available": False, "error": "Could not parse termux-sensor output"}

    magnitudes = []
    for reading_set in (data.values() if isinstance(data, dict) else []):
        entries = reading_set if isinstance(reading_set, list) else [reading_set]
        for reading in entries:
            values = reading.get("values") if isinstance(reading, dict) else None
            if values and len(values) >= 3:
                magnitudes.append((values[0] ** 2 + values[1] ** 2 + values[2] ** 2) ** 0.5)

    if not magnitudes:
        return {"available": True, "mode": mode, "samples": 0,
                "note": "Sensor responded but no magnitude readings parsed"}

    mean_ut = statistics.mean(magnitudes)
    max_ut = max(magnitudes)
    min_ut = min(magnitudes)
    spread = max_ut - min_ut

    # Earth's natural field is ~25-65 microtesla. A large spread during
    # a stationary reading, or an absolute value far outside that band,
    # suggests a nearby magnetic source (motor, coil, battery) rather
    # than ambient geomagnetism.
    flags = []
    if max_ut > 150 or spread > 40:
        flags.append({
            "type": "MAGNETIC_ANOMALY",
            "max_uT": round(max_ut, 1),
            "spread_uT": round(spread, 1),
            "reason": "Magnetic field reading well outside Earth's natural range "
                      "(25-65 uT) - sweep the area slowly, a rising reading points "
                      "toward the source",
        })

    return {
        "available": True, "mode": mode, "samples": len(magnitudes),
        "mean_uT": round(mean_ut, 1), "max_uT": round(max_ut, 1),
        "min_uT": round(min_ut, 1), "flags": flags,
    }


# ─────────────────────────────────────────────────────────────────────
# RF DETECTION - OPTIONAL SDR WIDEBAND SWEEP (real RF, not metadata)
# ─────────────────────────────────────────────────────────────────────

def sdr_spectrum_sweep(shell, freq_start_hz=300e6, freq_stop_hz=928e6, bin_hz=1e6, integrate_sec=5):
    """
    Optional real RF power sweep using a USB-OTG RTL-SDR dongle.
    Requires: pkg install rtl-sdr, plus a connected RTL-SDR dongle.
    Sweeps common ISM/surveillance bands (default 300-928 MHz covers
    most analog bug/wireless-camera transmitters) using rtl_power, then
    flags any bin sitting well above the local noise floor - this is
    an actual measured transmitter, not a metadata inference like the
    Wi-Fi/cellular heuristics above.
    """
    if not shell.has_local_binary("rtl_power"):
        return {"available": False,
                "error": "rtl_power not found (pkg install rtl-sdr) or no RTL-SDR dongle attached"}

    tmp_dir = "/data/data/com.termux/files/usr/tmp"
    out_file = os.path.join(tmp_dir if os.path.isdir(tmp_dir) else "/tmp", "ctf_rf_sweep.csv")

    cmd = [
        "rtl_power", "-f", f"{int(freq_start_hz)}:{int(freq_stop_hz)}:{int(bin_hz)}",
        "-i", str(integrate_sec), "-1", out_file,
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=integrate_sec + 30)
    except FileNotFoundError:
        return {"available": False, "error": "rtl_power failed to execute"}
    except subprocess.TimeoutExpired:
        return {"available": False, "error": "rtl_power timed out - check dongle connection"}

    if not os.path.exists(out_file):
        return {"available": False, "error": "rtl_power produced no output - check dongle/antenna"}

    powers = []
    try:
        with open(out_file) as f:
            for line in f:
                cols = line.strip().split(",")
                if len(cols) < 7:
                    continue
                low_hz, step_hz = float(cols[2]), float(cols[4])
                readings = [float(x) for x in cols[6:] if x.strip()]
                for i, db in enumerate(readings):
                    powers.append({"freq_hz": low_hz + i * step_hz, "power_db": db})
    finally:
        try:
            os.remove(out_file)
        except OSError:
            pass

    if not powers:
        return {"available": True, "bins": 0, "peaks": []}

    levels = [p["power_db"] for p in powers]
    noise_floor = statistics.median(levels)
    threshold = noise_floor + 15  # 15 dB above local noise floor = a real signal, not noise

    peaks = sorted(
        [p for p in powers if p["power_db"] >= threshold],
        key=lambda p: p["power_db"], reverse=True
    )[:15]

    return {
        "available": True, "bins": len(powers), "noise_floor_db": round(noise_floor, 1),
        "peaks": [{"freq_mhz": round(p["freq_hz"] / 1e6, 3), "power_db": round(p["power_db"], 1)} for p in peaks],
    }


# ─────────────────────────────────────────────────────────────────────
# PERSISTENCE DETECTION - installed package inventory
# ─────────────────────────────────────────────────────────────────────

def list_packages(shell):
    """
    `pm list packages -f -i` returns one line per package:
      package:/data/app/.../base.apk=com.example.app installer=com.android.vending
    Prefers ADB (shell UID isn't subject to Android 11+ package
    visibility filtering the way an app's own process is) but falls
    back to local execution when this code is already running with
    shell-level access inside Termux.
    """
    out, mode = shell.run(["pm", "list", "packages", "-f", "-i"], prefer="adb", timeout=20)
    if not out:
        return {"available": False, "error": "pm unavailable - connect via ADB (USB debugging) "
                "or run from Termux with shell access"}

    packages = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):]
        m = re.match(r"^(.*)=([^\s=]+)(?:\s+installer=(\S+))?$", body)
        if not m:
            continue
        apk_path, pkg_name, installer = m.group(1), m.group(2), m.group(3)
        packages[pkg_name] = {
            "apk_path": apk_path,
            "installer": installer if installer and installer != "null" else None,
        }
    return {"available": True, "mode": mode, "packages": packages}


def _non_system(packages):
    return {p: m for p, m in packages.items() if not m.get("apk_path", "").startswith("/system/")}


# ─────────────────────────────────────────────────────────────────────
# PERSISTENCE DETECTION - individual audits
# ─────────────────────────────────────────────────────────────────────

def accessibility_services_audit(shell):
    """
    Accessibility Service abuse is the #1 persistence/surveillance
    mechanism for Android stalkerware and banking RATs - it grants an
    app the ability to read screen content and inject input
    system-wide, and unlike most permissions it survives a casual
    "review your app permissions" check because users don't associate
    it with spying.
    """
    out, mode = shell.run(
        ["settings", "get", "secure", "enabled_accessibility_services"], prefer="adb", timeout=10
    )
    if out is None:
        return {"available": False, "error": "settings command unavailable"}
    enabled = [s.strip() for s in out.strip().split(":") if s.strip() and s.strip() != "null"]
    return {"available": True, "mode": mode, "enabled_services": enabled}


def device_admin_audit(shell):
    """Same dpm list-owners approach Module 5 uses, plus the full admin component list."""
    owners, mode = shell.run(["dpm", "list-owners"], prefer="adb", timeout=10)
    admins_raw, _ = shell.run(["dumpsys", "device_policy"], prefer="adb", timeout=10)
    admins = re.findall(r"Admin:\s*ComponentInfo\{([^}]+)\}", admins_raw) if admins_raw else []
    return {
        "available": mode is not None,
        "mode": mode,
        "owners": [l.strip() for l in owners.splitlines() if l.strip()] if owners else [],
        "admins": admins,
    }


def boot_persistence_audit(shell, packages):
    """
    Flags non-system apps that register a BOOT_COMPLETED receiver -
    the standard mechanism for surviving a reboot without user
    interaction. Not inherently malicious on its own (plenty of
    legitimate apps use it), but combined with a hidden launcher icon
    or a sideloaded APK it's a strong persistence signal. Scoped to
    non-system packages to keep the per-package dumpsys calls fast.
    """
    flagged = []
    for pkg in _non_system(packages):
        out, _mode = shell.run(["dumpsys", "package", pkg], prefer="adb", timeout=10)
        if out and "android.intent.action.BOOT_COMPLETED" in out:
            flagged.append(pkg)
    return {"packages_with_boot_receiver": flagged}


def overlay_permission_audit(shell, packages):
    """SYSTEM_ALERT_WINDOW: draws over other apps - phishing overlays, invisible keyloggers."""
    flagged = []
    for pkg in _non_system(packages):
        out, _mode = shell.run(["appops", "get", pkg, "SYSTEM_ALERT_WINDOW"], prefer="adb", timeout=10)
        if out and "allow" in out.lower():
            flagged.append(pkg)
    return {"packages_with_overlay_grant": flagged}


def hidden_launcher_audit(shell, packages):
    """
    Apps installed but with no launchable activity resolvable via the
    home-screen launcher intent are invisible in the app drawer - the
    classic "install it, hide the icon" stalkerware setup step. Scoped
    to non-system packages.
    """
    hidden = []
    for pkg in _non_system(packages):
        resolved, _mode = shell.run(
            ["cmd", "package", "resolve-activity", "--brief", pkg], prefer="adb", timeout=8
        )
        if resolved is not None and ("No activity found" in resolved or resolved.strip() == ""):
            hidden.append(pkg)
    return {"hidden_from_launcher": hidden}


def sideload_audit(packages):
    """
    Flags non-system packages not installed via a recognized app
    store. Sideloading isn't proof of anything by itself (F-Droid, APK
    mirrors, and developers all sideload legitimately) but it's a
    prerequisite for nearly all stalkerware installs, since none of it
    is distributed through Play Store.
    """
    known_stores = {
        "com.android.vending": "Google Play",
        "com.google.android.packageinstaller": "Play/system installer",
        "org.fdroid.fdroid": "F-Droid",
        "com.amazon.venezia": "Amazon Appstore",
        "com.sec.android.app.samsungapps": "Samsung Galaxy Store",
    }
    flagged = []
    for pkg, meta in _non_system(packages).items():
        installer = meta.get("installer")
        if installer not in known_stores:
            flagged.append({"package": pkg, "installer": installer or "UNKNOWN (adb install / APK sideload)"})
    return {"sideloaded_non_system_apps": flagged}


def load_stalkerware_db():
    """
    Load a local stalkerware/spyware package-name signature database.
    Ships empty - same pattern as Module 5's OUI/TAC databases - because
    a stale or fabricated "known spyware" list is worse than none.

    Populate ctf/data/stalkerware/signatures.json yourself from a
    vetted, actively-maintained IOC feed: Amnesty International's
    Mobile Verification Toolkit (github.com/mvt-project/mvt), the
    Coalition Against Stalkerware (coalitionagainststalkerware.org),
    or the EFF. Schema:
        {"com.example.knownspyware": {"name": "...", "category": "...",
                                       "source": "..."}}
    """
    db_file = DATA_DIR / "stalkerware" / "signatures.json"
    if not db_file.exists():
        return {}
    try:
        with open(db_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


_STALKERWARE_DB = None


def stalkerware_signature_check(package_names):
    global _STALKERWARE_DB
    if _STALKERWARE_DB is None:
        _STALKERWARE_DB = load_stalkerware_db()

    matches = [{"package": pkg, **_STALKERWARE_DB[pkg]} for pkg in package_names if pkg in _STALKERWARE_DB]
    return {
        "db_loaded": len(_STALKERWARE_DB) > 0,
        "db_entries": len(_STALKERWARE_DB),
        "matches": matches,
    }


def play_protect_status(shell):
    out, mode = shell.run(
        ["settings", "get", "global", "package_verifier_enable"], prefer="adb", timeout=10
    )
    return {
        "available": mode is not None,
        "mode": mode,
        "package_verifier_enabled": out.strip() if out else None,
    }


# ─────────────────────────────────────────────────────────────────────
# PERSISTENCE DETECTION - combined risk scoring
# ─────────────────────────────────────────────────────────────────────

def score_persistence_risk(packages, accessibility_services, admins, boot_receivers,
                            overlays, hidden, sideloaded, stalkerware_matches):
    """
    Combine every check above into a per-package risk picture. Single
    signals (sideloaded, hidden icon, accessibility enabled) are
    common and often innocent on their own. It's the COMBINATION that
    matters - that's what this scoring rewards.
    """
    accessibility_pkgs = {svc.split("/")[0] for svc in accessibility_services if svc}
    admin_pkgs = {re.split(r"[/\s]", a)[0] for a in admins if a}
    boot_set = set(boot_receivers)
    overlay_set = set(overlays)
    hidden_set = set(hidden)
    sideload_set = {e["package"] for e in sideloaded}
    stalker_set = {m["package"] for m in stalkerware_matches}

    all_flagged = (accessibility_pkgs | admin_pkgs | boot_set | overlay_set |
                   hidden_set | sideload_set | stalker_set)

    scored = []
    for pkg in sorted(all_flagged):
        signals = []
        score = 0
        if pkg in stalker_set:
            signals.append("KNOWN_STALKERWARE_SIGNATURE")
            score += 100
        if pkg in accessibility_pkgs:
            signals.append("ACCESSIBILITY_SERVICE_ENABLED")
            score += 25
        if pkg in hidden_set:
            signals.append("HIDDEN_FROM_LAUNCHER")
            score += 15
        if pkg in sideload_set:
            signals.append("SIDELOADED")
            score += 10
        if pkg in boot_set:
            signals.append("BOOT_PERSISTENCE_RECEIVER")
            score += 15
        if pkg in overlay_set:
            signals.append("SCREEN_OVERLAY_GRANTED")
            score += 15
        if pkg in admin_pkgs:
            signals.append("DEVICE_ADMIN")
            score += 15

        # Combination bonuses - this is where noise becomes signal
        if pkg in accessibility_pkgs and pkg in hidden_set:
            score += 25
        if pkg in accessibility_pkgs and pkg in sideload_set:
            score += 15
        if pkg in hidden_set and pkg in sideload_set:
            score += 20
        if pkg in hidden_set and pkg in boot_set:
            score += 20
        if pkg in sideload_set and (pkg in admin_pkgs or pkg in overlay_set):
            score += 15

        if score >= 100:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"

        scored.append({"package": pkg, "score": score, "level": level, "signals": signals})

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


# ─────────────────────────────────────────────────────────────────────
# ORCHESTRATOR CLASSES
# ─────────────────────────────────────────────────────────────────────

class RFDetector:
    """RF surveillance sweep: Wi-Fi, cellular, magnetic, optional SDR."""

    def __init__(self, journal=None, shell=None):
        self.journal = journal or EvidenceJournal()
        self.shell = shell or DeviceShell()

    def scan(self, sdr=False, sdr_range_mhz=(300, 928)):
        print("\n[CTF/M9] RF surveillance sweep")
        result = {"timestamp": datetime.now(timezone.utc).isoformat(), "flags": []}

        wifi = wifi_scan(self.shell)
        wifi_analysis = analyze_wifi_scan(wifi) if wifi.get("available") else {"flags": []}
        self.journal.log(
            module="m9_rf_persistence", query="WIFI_SCAN", source="termux-wifi-scaninfo",
            response={**wifi, **wifi_analysis} if wifi.get("available") else wifi,
        )
        result["wifi"] = {**wifi, "analysis": wifi_analysis}
        result["flags"].extend(wifi_analysis.get("flags", []))
        if wifi.get("available"):
            print(f"  Wi-Fi: {wifi_analysis.get('ap_count', 0)} access points, "
                  f"{len(wifi_analysis.get('flags', []))} flag(s)")
        else:
            print(f"  Wi-Fi: {wifi.get('error')}")

        cell = cellular_scan(self.shell)
        cell_analysis = analyze_cellular_scan(cell) if cell.get("available") else {"flags": []}
        self.journal.log(
            module="m9_rf_persistence", query="CELLULAR_SCAN", source="termux-telephony-cellinfo",
            response={**cell, **cell_analysis} if cell.get("available") else cell,
        )
        result["cellular"] = {**cell, "analysis": cell_analysis}
        result["flags"].extend(cell_analysis.get("flags", []))
        if cell.get("available"):
            print(f"  Cellular: {cell_analysis.get('cell_count', 0)} towers visible, "
                  f"{len(cell_analysis.get('flags', []))} flag(s)")
        else:
            print(f"  Cellular: {cell.get('error')}")

        mag = magnetic_field_sweep(self.shell)
        self.journal.log(module="m9_rf_persistence", query="MAGNETIC_SWEEP", source="termux-sensor", response=mag)
        result["magnetic"] = mag
        result["flags"].extend(mag.get("flags", []))
        if mag.get("available"):
            print(f"  Magnetic field: {mag.get('mean_uT', '?')} uT mean, {mag.get('max_uT', '?')} uT peak")
        else:
            print(f"  Magnetic: {mag.get('error')}")

        if sdr:
            lo, hi = sdr_range_mhz
            sweep = sdr_spectrum_sweep(self.shell, lo * 1e6, hi * 1e6)
            self.journal.log(
                module="m9_rf_persistence", query=f"SDR_SWEEP {lo}-{hi}MHz",
                source="rtl_power/RTL-SDR", response=sweep,
            )
            result["sdr_sweep"] = sweep
            if sweep.get("available"):
                print(f"  SDR sweep: {sweep.get('bins', 0)} bins, {len(sweep.get('peaks', []))} peak(s) "
                      f"above noise floor")
                for peak in sweep.get("peaks", [])[:5]:
                    print(f"    -> {peak['freq_mhz']} MHz @ {peak['power_db']} dB")
            else:
                print(f"  SDR sweep: {sweep.get('error')}")

        print(f"\n  Total RF flags: {len(result['flags'])}")
        for f in result["flags"]:
            print(f"    \U0001F6A9 {f.get('type')}: {f.get('reason')}")

        return result


class PersistenceDetector:
    """Own-device stalkerware/RAT persistence audit."""

    def __init__(self, journal=None, shell=None):
        self.journal = journal or EvidenceJournal()
        self.shell = shell or DeviceShell()

    def scan(self):
        print("\n[CTF/M9] Persistence forensics (own device)")
        result = {"timestamp": datetime.now(timezone.utc).isoformat()}

        pkgs = list_packages(self.shell)
        self.journal.log(
            module="m9_rf_persistence", query="PM_LIST_PACKAGES", source="pm/shell",
            response={"available": pkgs.get("available"), "count": len(pkgs.get("packages", {}))},
        )
        result["packages_available"] = pkgs.get("available", False)

        if not pkgs.get("available"):
            result["error"] = pkgs.get("error")
            print(f"  {pkgs.get('error')}")
            return result

        packages = pkgs["packages"]
        print(f"  {len(packages)} packages installed")

        accessibility = accessibility_services_audit(self.shell)
        self.journal.log(module="m9_rf_persistence", query="ACCESSIBILITY_SERVICES",
                          source="settings/secure", response=accessibility)

        admin = device_admin_audit(self.shell)
        self.journal.log(module="m9_rf_persistence", query="DEVICE_ADMIN",
                          source="dpm/dumpsys", response=admin)

        boot = boot_persistence_audit(self.shell, packages)
        self.journal.log(module="m9_rf_persistence", query="BOOT_RECEIVER_AUDIT",
                          source="dumpsys package", response=boot)

        overlay = overlay_permission_audit(self.shell, packages)
        self.journal.log(module="m9_rf_persistence", query="OVERLAY_AUDIT",
                          source="appops", response=overlay)

        hidden = hidden_launcher_audit(self.shell, packages)
        self.journal.log(module="m9_rf_persistence", query="HIDDEN_LAUNCHER_AUDIT",
                          source="cmd package resolve-activity", response=hidden)

        sideload = sideload_audit(packages)
        self.journal.log(module="m9_rf_persistence", query="SIDELOAD_AUDIT",
                          source="pm list packages -i", response=sideload)

        stalker = stalkerware_signature_check(list(packages.keys()))
        self.journal.log(module="m9_rf_persistence", query="STALKERWARE_SIGNATURE_CHECK",
                          source="local-signature-db", response=stalker)

        protect = play_protect_status(self.shell)
        self.journal.log(module="m9_rf_persistence", query="PLAY_PROTECT_STATUS",
                          source="settings/global", response=protect)

        scored = score_persistence_risk(
            packages,
            accessibility_services=accessibility.get("enabled_services", []),
            admins=admin.get("admins", []),
            boot_receivers=boot.get("packages_with_boot_receiver", []),
            overlays=overlay.get("packages_with_overlay_grant", []),
            hidden=hidden.get("hidden_from_launcher", []),
            sideloaded=sideload.get("sideloaded_non_system_apps", []),
            stalkerware_matches=stalker.get("matches", []),
        )

        result.update({
            "accessibility": accessibility, "device_admin": admin, "boot_persistence": boot,
            "overlay": overlay, "hidden_launcher": hidden, "sideload": sideload,
            "stalkerware": stalker, "play_protect": protect, "risk_scored": scored,
        })

        if accessibility.get("enabled_services"):
            print(f"  Accessibility services enabled: {len(accessibility['enabled_services'])}")
            for svc in accessibility["enabled_services"]:
                print(f"    -> {svc}")
        if admin.get("admins"):
            print(f"  Device admins: {admin['admins']}")
        if hidden.get("hidden_from_launcher"):
            print(f"  Hidden from launcher: {len(hidden['hidden_from_launcher'])}")
        if sideload.get("sideloaded_non_system_apps"):
            print(f"  Sideloaded (non-store) apps: {len(sideload['sideloaded_non_system_apps'])}")
        if stalker.get("matches"):
            print(f"  \U0001F6A8 STALKERWARE SIGNATURE MATCH: {[m['package'] for m in stalker['matches']]}")

        if scored:
            print(f"\n  Risk-scored packages ({len(scored)}):")
            for s in scored[:10]:
                print(f"    [{s['level']:8}] {s['package']}  score={s['score']}  {', '.join(s['signals'])}")
        else:
            print("\n  No persistence indicators found.")

        return result


class RFPersistenceForensics:
    """
    Top-level entry point Module 9 exposes to main.py, matching the
    naming convention of Module 5's DeviceIdentityForensics.
    """

    def __init__(self, journal=None):
        self.journal = journal or EvidenceJournal()
        self.shell = DeviceShell()
        self.rf = RFDetector(journal=self.journal, shell=self.shell)
        self.persistence = PersistenceDetector(journal=self.journal, shell=self.shell)

    def scan_rf(self, sdr=False, sdr_range_mhz=(300, 928)):
        return self.rf.scan(sdr=sdr, sdr_range_mhz=sdr_range_mhz)

    def scan_persistence(self):
        return self.persistence.scan()


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 9 RF & Persistence Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        m9 = RFPersistenceForensics(journal=journal)

        print("\nTest 1: RF sweep (no termux-api / SDR expected in test env)")
        rf_result = m9.scan_rf()
        print(f"  Wi-Fi available: {rf_result['wifi'].get('available')}")
        print(f"  Cellular available: {rf_result['cellular'].get('available')}")
        print(f"  Magnetic available: {rf_result['magnetic'].get('available')}")

        print("\nTest 2: Persistence scan (no adb/pm expected in test env)")
        p_result = m9.scan_persistence()
        print(f"  Packages available: {p_result.get('packages_available')}")

        print("\nTest 3: Wi-Fi evil-twin heuristic (synthetic data)")
        synthetic = {
            "available": True,
            "access_points": [
                {"bssid": "AA:BB:CC:11:22:33", "ssid": "CoffeeShop-WiFi", "level": -55},
                {"bssid": "11:22:33:44:55:66", "ssid": "CoffeeShop-WiFi", "level": -40},
                {"bssid": "DE:AD:BE:EF:00:01", "ssid": "", "level": -35},
            ],
        }
        analysis = analyze_wifi_scan(synthetic)
        print(f"  Flags raised: {len(analysis['flags'])}")
        for f in analysis["flags"]:
            print(f"    -> {f['type']}: {f['reason']}")
        assert len(analysis["flags"]) == 2, "Expected evil-twin + strong-hidden-SSID flags"

        print("\nTest 4: Cellular 2G-downgrade heuristic (synthetic data)")
        synthetic_cell = {"available": True, "cells": [
            {"type": "gsm", "registered": True, "dbm": -50},
        ]}
        cell_analysis = analyze_cellular_scan(synthetic_cell)
        print(f"  Flags raised: {len(cell_analysis['flags'])}")
        for f in cell_analysis["flags"]:
            print(f"    -> {f['type']}: {f['reason']}")
        assert len(cell_analysis["flags"]) >= 1, "Expected 2G downgrade / isolated-cell flag"

        print("\nTest 5: Persistence risk scoring (synthetic data)")
        scored = score_persistence_risk(
            packages={"com.example.spy": {"apk_path": "/data/app/com.example.spy", "installer": None}},
            accessibility_services=["com.example.spy/.AccessibilityService"],
            admins=[],
            boot_receivers=["com.example.spy"],
            overlays=["com.example.spy"],
            hidden=["com.example.spy"],
            sideloaded=[{"package": "com.example.spy", "installer": None}],
            stalkerware_matches=[],
        )
        print(f"  Scored packages: {len(scored)}")
        for s in scored:
            print(f"    [{s['level']}] {s['package']} score={s['score']} signals={s['signals']}")
        assert scored[0]["level"] in ("HIGH", "CRITICAL"), "Expected combined signals to score HIGH+"

        print("\n" + "-" * 40)
        v = journal.verify()
        print(f"Evidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 9 self-test complete.")
        print("=" * 60)
