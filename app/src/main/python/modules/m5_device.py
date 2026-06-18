#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 5 - Device Identity & Telecom Forensics

One job: Turn a device identifier (IMEI, ICCID, serial, MAC) into
a complete device identity picture. Cross-reference stolen device
databases. Decode manufacturer information from public databases.

Data sources (all local or direct query, no subscriptions):
  - CTIA IMEI DB:   imeicheck.com/api (free tier, IMEI validation)
  - FCC DB:         apps.fcc.gov/oetcf/eas (equipment authorization, free)
  - IEEE OUI:       standards-oui.ieee.org (local download, free)
  - GSMA TAC:       imeidb.gsma.com (TAC lookup, free)
  - ADB commands:   Run against your own device via USB
  - SMS loop-back:  Send SMS to yourself, check delivery (OWN device only)

All device lookups in this module are designed for:
  1. Checking YOUR OWN device for compromise signs
  2. Looking up devices reported as stolen
  3. Verifying device authenticity in legal investigations

ADB and SMS tests MUST only be used on devices you own or have
explicit legal authority to test.
"""

import subprocess
import json
import re
import os
import sys
import struct
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal

DATA_DIR = Path(__file__).parent.parent / "data"


# ─────────────────────────────────────────────────────────────────────
# OUI DATABASE (IEEE - MAC Address Manufacturer Lookup)
# ─────────────────────────────────────────────────────────────────────

def load_oui_database():
    """
    Load IEEE OUI database from local file.
    Download: wget https://standards-oui.ieee.org/oui/oui.txt
    Place at: ctf/data/oui/oui.txt
    
    Returns dict mapping OUI prefix → manufacturer name.
    """
    oui_file = DATA_DIR / "oui" / "oui.txt"
    if not oui_file.exists():
        return {}

    oui_map = {}
    try:
        with open(oui_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # Format: AA-BB-CC   (hex)  Manufacturer Name
                match = re.match(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line.strip())
                if match:
                    oui = match.group(1).replace("-", ":").upper()
                    manufacturer = match.group(2).strip()
                    oui_map[oui] = manufacturer
    except Exception:
        pass

    return oui_map


_OUI_DB = None


def oui_lookup(mac_address):
    """
    Look up MAC address manufacturer from local IEEE OUI database.
    Runs entirely offline. No external query.
    """
    global _OUI_DB
    if _OUI_DB is None:
        _OUI_DB = load_oui_database()

    result = {
        "mac":          mac_address,
        "oui":          None,
        "manufacturer": None,
        "db_loaded":    len(_OUI_DB) > 0,
        "error":        None,
    }

    # Normalize MAC to XX:XX:XX:XX:XX:XX
    clean = re.sub(r"[^0-9a-fA-F]", "", mac_address).upper()
    if len(clean) != 12:
        result["error"] = "Invalid MAC address length"
        return result

    formatted = ":".join(clean[i:i+2] for i in range(0, 12, 2))
    oui_prefix = ":".join(formatted.split(":")[:3])
    result["oui"] = oui_prefix

    if _OUI_DB:
        result["manufacturer"] = _OUI_DB.get(oui_prefix, "Unknown manufacturer")
    else:
        result["error"] = "OUI database not loaded. Download from standards-oui.ieee.org"

    return result


# ─────────────────────────────────────────────────────────────────────
# IMEI ANALYSIS
# ─────────────────────────────────────────────────────────────────────

def luhn_check(number):
    """Luhn algorithm for IMEI validity check."""
    digits = [int(d) for d in str(number)]
    checksum = 0
    for i, d in enumerate(digits[::-1]):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def decode_imei(imei):
    """
    Decode IMEI structure. All local, no external query.
    
    IMEI structure:
      TAC (8 digits): Type Allocation Code - identifies device model
      SNR (6 digits): Serial Number
      CD  (1 digit):  Luhn check digit
    """
    if len(imei) != 15 or not imei.isdigit():
        return {"error": "Invalid IMEI format"}

    result = {
        "imei":        imei,
        "tac":         imei[:8],
        "snr":         imei[8:14],
        "check_digit": imei[14],
        "luhn_valid":  luhn_check(imei),
    }

    # TAC prefix decoding (first 2 digits = reporting body)
    reporting_body = {
        "01": "BABT (UK)",
        "10": "CETECOM (Spain)",
        "30": "KOTSA (Japan)",
        "35": "BABT (UK)",
        "44": "BABT (UK)",
        "45": "BABT (UK)",
        "49": "BAIC (Germany)",
        "50": "BABT (UK)",
        "86": "CAICT (China)",
        "91": "TATA (India)",
        "98": "BABT (UK)",
    }

    tac_prefix = imei[:2]
    result["reporting_body"] = reporting_body.get(tac_prefix, f"Unknown ({tac_prefix})")

    return result


def gsma_tac_lookup(tac):
    """
    Look up device type from GSMA TAC (Type Allocation Code) database.
    
    Primary: Local GSMA database file (ctf/data/tac/tac_db.json)
    Fallback: GSMA IMEI DB API (free basic lookup)
    
    TAC identifies the device model (e.g. "35693803" = specific iPhone model)
    """
    result = {
        "tac":          tac,
        "manufacturer": None,
        "model":        None,
        "device_type":  None,
        "os":           None,
        "error":        None,
    }

    # Try local database first
    tac_file = DATA_DIR / "tac" / "tac_db.json"
    if tac_file.exists():
        try:
            with open(tac_file, "r") as f:
                tac_db = json.load(f)
            if tac in tac_db:
                entry = tac_db[tac]
                result.update({
                    "manufacturer": entry.get("brand"),
                    "model":        entry.get("model"),
                    "device_type":  entry.get("deviceType"),
                    "os":           entry.get("operatingSystem"),
                })
                return result
        except Exception:
            pass

    # Fallback: GSMA API
    try:
        url = f"https://imeidb.gsma.com/imei/tac/{tac}"
        req = Request(url, headers={
            "User-Agent": "CTF-Forensics/1.0",
            "Accept": "application/json",
        })
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        result.update({
            "manufacturer": data.get("brand"),
            "model":        data.get("model"),
            "device_type":  data.get("deviceType"),
            "os":           data.get("operatingSystem"),
        })

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# FCC EQUIPMENT AUTHORIZATION
# ─────────────────────────────────────────────────────────────────────

def fcc_equipment_search(fcc_id):
    """
    Look up FCC equipment authorization by FCC ID.
    Direct query to FCC public database.
    
    FCC IDs are printed on devices sold in the US.
    They encode grantee code + product code.
    """
    result = {
        "fcc_id":     fcc_id,
        "grantee":    None,
        "description": None,
        "date":        None,
        "error":       None,
    }

    try:
        url = f"https://apps.fcc.gov/oetcf/eas/reports/GetApplicationInfo.cfm?request_type=SEARCH&search_type=Equipment+Authorization&fcc_id={fcc_id}"
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="replace")

        # Parse HTML response (FCC API returns HTML)
        grantee = re.search(r"Grantee Name:\s*</[^>]+>\s*<[^>]+>([^<]+)", content)
        desc    = re.search(r"Equipment Class:\s*</[^>]+>\s*<[^>]+>([^<]+)", content)
        date    = re.search(r"Grant Date:\s*</[^>]+>\s*<[^>]+>([^<]+)", content)

        if grantee:
            result["grantee"] = grantee.group(1).strip()
        if desc:
            result["description"] = desc.group(1).strip()
        if date:
            result["date"] = date.group(1).strip()

        if not result["grantee"]:
            result["error"] = "FCC ID not found or no authorization data"

    except (URLError, HTTPError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# ADB DEVICE FORENSICS (OWN DEVICE ONLY)
# ─────────────────────────────────────────────────────────────────────

def adb_device_info():
    """
    Extract device identity information via ADB from YOUR OWN device.
    
    Requires:
      - ADB installed (or static binary in ctf/bin/)
      - USB debugging enabled on target device
      - Device connected via USB
    
    LEGAL NOTE: This MUST only be used on devices you own or have
    explicit legal authorization to examine.
    
    Returns comprehensive device identity including:
      - IMEI, MEID
      - Serial number
      - Android ID (unique per device, reset on factory reset)
      - Installed MDM profiles
      - Device admin apps
      - Network interfaces and MAC addresses
    """
    result = {
        "connected":     False,
        "imei":          None,
        "serial":        None,
        "android_id":    None,
        "model":         None,
        "manufacturer":  None,
        "android_ver":   None,
        "mac_wifi":      None,
        "mac_bt":        None,
        "device_admins": [],
        "mdm_indicators": [],
        "provisioning_mode": None,
        "error":         None,
    }

    # Find ADB binary
    adb_paths = [
        "adb",
        os.path.expanduser("~/bin/adb"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "adb"),
    ]

    adb_bin = None
    for path in adb_paths:
        try:
            subprocess.run([path, "version"], capture_output=True, timeout=5)
            adb_bin = path
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if not adb_bin:
        result["error"] = "ADB not found. Install dnsutils package or put static binary in ctf/bin/"
        return result

    def adb(cmd):
        """Run an ADB command and return stdout."""
        try:
            proc = subprocess.run(
                [adb_bin] + cmd.split(),
                capture_output=True, text=True, timeout=10
            )
            return proc.stdout.strip()
        except subprocess.TimeoutExpired:
            return None

    # Check device connected
    devices = adb("devices")
    if not devices or "device" not in devices:
        result["error"] = "No ADB device connected"
        return result
    result["connected"] = True

    # Basic device properties
    result["model"]        = adb("shell getprop ro.product.model")
    result["manufacturer"] = adb("shell getprop ro.product.manufacturer")
    result["android_ver"]  = adb("shell getprop ro.build.version.release")
    result["serial"]       = adb("get-serialno")

    # IMEI (requires privileged access on Android 10+)
    imei_raw = adb("shell service call iphonesubinfo 1 s16 com.android.shell")
    if imei_raw:
        digits = re.findall(r"\d+", imei_raw)
        if len(digits) >= 15:
            imei_candidate = "".join(digits[-15:])
            if len(imei_candidate) == 15:
                result["imei"] = imei_candidate

    # Android ID (changes on factory reset)
    result["android_id"] = adb(
        "shell settings get secure android_id"
    )

    # WiFi MAC address
    mac_raw = adb("shell cat /sys/class/net/wlan0/address")
    if mac_raw and ":" in mac_raw:
        result["mac_wifi"] = mac_raw.upper()

    # Bluetooth MAC
    bt_raw = adb("shell settings get secure bluetooth_address")
    if bt_raw and ":" in bt_raw:
        result["mac_bt"] = bt_raw.upper()

    # Device admin apps (MDM agents appear here)
    admins_raw = adb(
        "shell dpm list-owners"
    )
    if admins_raw:
        for line in admins_raw.split("\n"):
            line = line.strip()
            if line and "package" in line.lower():
                result["device_admins"].append(line)

    # Android enterprise provisioning state
    provision = adb(
        "shell getprop ro.boot.provision"
    )
    dpc_package = adb(
        "shell getprop persist.sys.device_policy_owner"
    )
    enterprise_enrolled = adb(
        "shell getprop ro.organization_managed"
    )

    indicators = []
    if provision and provision not in ("", "0"):
        indicators.append(f"PROVISIONED: {provision}")
    if dpc_package:
        indicators.append(f"DPC_OWNER: {dpc_package}")
    if enterprise_enrolled == "1":
        indicators.append("ENTERPRISE_ENROLLED")

    # Check for known MDM package names
    packages_raw = adb("shell pm list packages -f")
    if packages_raw:
        mdm_packages = {
            "com.mobileiron":           "MobileIron",
            "com.airwatch":             "VMware Workspace ONE",
            "com.jamf":                 "Jamf",
            "com.meraki":               "Cisco Meraki",
            "com.microsoft.intune":     "Microsoft Intune",
            "com.google.android.apps.work.profile": "Android Enterprise",
            "com.samsung.android.knox": "Samsung Knox",
            "com.ibm.security.maasnewton": "IBM MaaS360",
            "com.citrix.mdx":           "Citrix",
        }
        for pkg_id, pkg_name in mdm_packages.items():
            if pkg_id in packages_raw:
                indicators.append(f"MDM_PACKAGE: {pkg_name} ({pkg_id})")

    result["mdm_indicators"] = indicators
    result["provisioning_mode"] = "ENTERPRISE_MANAGED" if indicators else "PERSONAL"

    return result


# ─────────────────────────────────────────────────────────────────────
# SMS LOOP-BACK TEST (OWN DEVICE ONLY)
# ─────────────────────────────────────────────────────────────────────

def sms_loopback_test(phone_number):
    """
    SIM cloning detection via SMS loop-back test.
    
    HOW IT WORKS:
      1. Send an SMS to your own phone number
      2. If delivered=True AND received=False: possible dual SIM provisioning
         (another device is receiving your messages)
      3. If delivered=True AND received=True: normal, your number is yours
      4. If delivered=False: network or sending problem
    
    This test MUST only be done on your own phone number.
    Sending SMS to someone else's number would be harassing them.
    
    WHAT THIS PROVES (if positive):
      - Your phone number is being served to another device simultaneously
      - This is consistent with SIM cloning or eSIM unauthorized provisioning
      - It does NOT prove which carrier is responsible
    
    WHAT THIS DOES NOT PROVE:
      - Who cloned the SIM
      - When it was cloned
      - That any specific person is responsible
    
    Args:
        phone_number: YOUR OWN phone number to test
        
    Returns:
        dict: Test instructions and result template
              (actual test must be run manually on device)
    """
    return {
        "test": "SMS_LOOPBACK",
        "target_number": phone_number,
        "instructions": [
            "1. On the device you're testing, send an SMS to yourself: " + phone_number,
            "2. Note the timestamp when you send it",
            "3. Wait 60 seconds",
            "4. Check if the SMS shows as 'Delivered'",
            "5. Check if you received the SMS in your inbox",
            "6. Record both outcomes below",
        ],
        "result_template": {
            "sent_at":      None,
            "delivered":    None,  # True/False - delivery receipt
            "received":     None,  # True/False - appeared in inbox
            "conclusion": (
                "If delivered=True AND received=False: "
                "POSSIBLE SIM CLONING OR DUAL PROVISIONING. "
                "Your number may be active on another device. "
                "Contact your carrier immediately and request "
                "an HLR lookup to verify device count."
            )
        },
        "next_steps_if_positive": [
            "Contact carrier and request HLR (Home Location Register) lookup",
            "File FCC complaint: consumercomplaints.fcc.gov",
            "Request CPNI (Customer Proprietary Network Information) disclosure",
            "Generate carrier demand letter via Module 9 Report Engine",
        ],
        "legal_note": (
            "This test is legal when run on your own number. "
            "The results are investigative intelligence. "
            "For legal proceedings, carrier HLR records constitute "
            "the authoritative evidence of device provisioning."
        )
    }


# ─────────────────────────────────────────────────────────────────────
# MAIN MODULE CLASS
# ─────────────────────────────────────────────────────────────────────

class DeviceIdentityForensics:
    """
    Takes a device identifier (IMEI, ICCID, MAC, serial).
    Returns complete device identity picture.
    Logs everything to evidence journal.
    """

    def __init__(self, journal=None):
        self.journal = journal or EvidenceJournal()

    def analyze_imei(self, imei):
        """Full IMEI analysis."""
        print(f"\n[CTF/M5] IMEI Analysis: {imei}")
        result = {"imei": imei, "timestamp": datetime.now(timezone.utc).isoformat()}

        # Decode structure
        decoded = decode_imei(imei)
        self.journal.log(
            module="m5_device",
            query=f"IMEI_DECODE: {imei}",
            source="local-Luhn+structure",
            response=decoded
        )
        result["decoded"] = decoded
        print(f"  TAC: {decoded.get('tac')} | Luhn valid: {decoded.get('luhn_valid')}")

        # TAC lookup
        if decoded.get("tac"):
            tac = gsma_tac_lookup(decoded["tac"])
            self.journal.log(
                module="m5_device",
                query=f"TAC_LOOKUP: {decoded['tac']}",
                source="GSMA-TAC-DB",
                response=tac
            )
            result["device"] = tac
            if tac.get("manufacturer"):
                print(f"  Device: {tac.get('manufacturer')} {tac.get('model')}")

        return result

    def analyze_mac(self, mac):
        """Full MAC address analysis."""
        print(f"\n[CTF/M5] MAC Analysis: {mac}")
        result = {"mac": mac, "timestamp": datetime.now(timezone.utc).isoformat()}

        oui = oui_lookup(mac)
        self.journal.log(
            module="m5_device",
            query=f"OUI_LOOKUP: {mac}",
            source="IEEE-OUI-local-DB",
            response=oui
        )
        result["oui"] = oui
        if oui.get("manufacturer"):
            print(f"  Manufacturer: {oui.get('manufacturer')}")
        elif not oui.get("db_loaded"):
            print(f"  OUI DB not loaded - download from standards-oui.ieee.org")

        return result

    def analyze_own_device(self):
        """
        Run comprehensive ADB analysis on the device connected via USB.
        MUST only be used on your own device.
        """
        print(f"\n[CTF/M5] ADB Device Analysis (own device)")
        info = adb_device_info()

        self.journal.log(
            module="m5_device",
            query="ADB_DEVICE_INFO",
            source="ADB/USB-direct",
            response={k: v for k, v in info.items() if k != "error"}
        )

        if info.get("error"):
            print(f"  Error: {info['error']}")
        else:
            print(f"  Model:    {info.get('manufacturer')} {info.get('model')}")
            print(f"  Android:  {info.get('android_ver')}")
            print(f"  IMEI:     {info.get('imei', 'Unavailable')}")
            print(f"  Serial:   {info.get('serial')}")
            print(f"  Mode:     {info.get('provisioning_mode')}")
            if info.get("mdm_indicators"):
                print(f"\n  MDM Indicators:")
                for ind in info["mdm_indicators"]:
                    print(f"    🚩 {ind}")
            if info.get("device_admins"):
                print(f"\n  Device Admins:")
                for admin in info["device_admins"]:
                    print(f"    → {admin}")

        return info

    def sms_loopback(self, phone_number):
        """Generate SMS loop-back test instructions for own device."""
        print(f"\n[CTF/M5] SMS Loop-back Test: {phone_number}")
        test = sms_loopback_test(phone_number)

        self.journal.log(
            module="m5_device",
            query=f"SMS_LOOPBACK_PREPARED: {phone_number}",
            source="local-test-generator",
            response={"target": phone_number, "test_type": "SIM cloning detection"}
        )

        print(f"  Instructions for SIM cloning detection:")
        for step in test["instructions"]:
            print(f"    {step}")

        return test


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 5 Device Identity Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        dev = DeviceIdentityForensics(journal=journal)

        # Test IMEI decode (no network needed)
        print("\nTest 1: IMEI decode")
        result = dev.analyze_imei("356938035643809")
        print(f"  TAC: {result['decoded']['tac']}")
        print(f"  SNR: {result['decoded']['snr']}")
        print(f"  Luhn: {result['decoded']['luhn_valid']}")
        print(f"  Reporting body: {result['decoded']['reporting_body']}")

        # Test MAC OUI (local DB needed)
        print("\nTest 2: MAC OUI lookup")
        result = dev.analyze_mac("AA:BB:CC:DD:EE:FF")
        if result["oui"].get("db_loaded"):
            print(f"  Manufacturer: {result['oui']['manufacturer']}")
        else:
            print(f"  OUI DB not loaded (expected in test env)")

        # Test SMS loopback instructions
        print("\nTest 3: SMS loop-back test instructions")
        test = dev.sms_loopback("+15125551234")
        print(f"  Test type: SIM cloning detection")
        print(f"  Steps: {len(test['instructions'])}")

        # Test ADB (won't connect in test env)
        print("\nTest 4: ADB device info (no device expected in test env)")
        info = dev.analyze_own_device()
        print(f"  Connected: {info['connected']}")
        if info.get("error"):
            print(f"  (Expected: {info['error']})")

        # Verify evidence chain
        print("\n" + "─" * 40)
        v = journal.verify()
        print(f"Evidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 5 self-test complete.")
        print("=" * 60)
