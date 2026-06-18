#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 0 - Input Router

One job: Accept anything. Figure out what it is. Route it correctly.

Accepts:
  - Domain name
  - IP address (v4 or v6)
  - Email address
  - Phone number
  - IMEI (15 digits, passes Luhn check)
  - ICCID (19-20 digits, starts with 89)
  - Serial number (alphanumeric, cross-referenced against known formats)
  - MAC address
  - Raw log file path

Everything that comes in gets logged to the evidence journal
before any processing begins.
"""

import re
import os
import sys

# Add parent directory to path so modules can import evidence_journal
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evidence_journal import EvidenceJournal


# ─────────────────────────────────────────────────────────────────────
# INPUT TYPE DEFINITIONS
# ─────────────────────────────────────────────────────────────────────

INPUT_TYPES = {
    "DOMAIN":       "Route to Module 1 (Infrastructure Fingerprinting)",
    "IPV4":         "Route to Module 1 (Infrastructure Fingerprinting)",
    "IPV6":         "Route to Module 1 (Infrastructure Fingerprinting)",
    "EMAIL":        "Route to Module 2 (Email & DNS Forensics)",
    "PHONE":        "Route to Module 2 (Email & DNS Forensics)",
    "IMEI":         "Route to Module 5 (Device Identity)",
    "ICCID":        "Route to Module 5 (Device Identity)",
    "SERIAL":       "Route to Module 5 (Device Identity)",
    "MAC":          "Route to Module 5 (Device Identity)",
    "LOG_FILE":     "Parse file for all identifier types, route each",
    "UNKNOWN":      "Cannot determine type - request clarification",
}


# ─────────────────────────────────────────────────────────────────────
# DETECTION PATTERNS
# ─────────────────────────────────────────────────────────────────────

# IPv4: four octets 0-255
PATTERN_IPV4 = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# IPv6: eight groups of hex, various compressed forms
PATTERN_IPV6 = re.compile(
    r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)

# Domain: at least one dot, valid TLD characters, no spaces
PATTERN_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Email: local@domain
PATTERN_EMAIL = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# Phone: 10-15 digits, optional +, spaces, dashes, parens
PATTERN_PHONE = re.compile(
    r"^\+?[\d\s\-\(\)]{10,17}$"
)

# IMEI: exactly 15 digits
PATTERN_IMEI = re.compile(
    r"^\d{15}$"
)

# ICCID: 19-20 digits starting with 89
PATTERN_ICCID = re.compile(
    r"^89\d{17,18}$"
)

# MAC address: 6 hex pairs with colon, dash, or no separator
PATTERN_MAC = re.compile(
    r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$"
    r"|^[0-9a-fA-F]{12}$"
)

# Serial number: 8-20 alphanumeric characters
# Loose pattern - confirmed by manufacturer format check
PATTERN_SERIAL = re.compile(
    r"^[A-Z0-9]{8,20}$"
)


# ─────────────────────────────────────────────────────────────────────
# LUHN ALGORITHM (IMEI VALIDATION)
# ─────────────────────────────────────────────────────────────────────

def luhn_check(number):
    """
    Validate a number string using the Luhn algorithm.
    Used to confirm IMEI format validity before lookup.
    Runs entirely locally. No external query.
    """
    digits = [int(d) for d in str(number)]
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ─────────────────────────────────────────────────────────────────────
# IPV4 VALIDATION
# ─────────────────────────────────────────────────────────────────────

def validate_ipv4(value):
    """Check all four octets are 0-255."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(0 <= int(p) <= 255 for p in parts if p.isdigit())


# ─────────────────────────────────────────────────────────────────────
# APPLE SERIAL FORMAT CHECK
# ─────────────────────────────────────────────────────────────────────

def is_apple_serial(value):
    """
    Apple serials are 11-12 chars, specific character set.
    Format encodes manufacturing date and location.
    No external query needed - format is documented.
    """
    if len(value) not in (11, 12):
        return False
    return bool(re.match(r"^[A-Z0-9]{11,12}$", value))


def decode_apple_serial(serial):
    """
    Decode manufacturing info from Apple serial number.
    Runs entirely locally from documented format.
    
    Returns dict with manufacturer details encoded in serial.
    """
    if not is_apple_serial(serial):
        return None

    # Year encoding (character 4 in 12-char, character 3 in 11-char)
    year_map = {
        "C": 2010, "D": 2011, "F": 2012, "G": 2013,
        "H": 2014, "J": 2015, "K": 2016, "L": 2017,
        "M": 2018, "N": 2019, "P": 2020, "Q": 2021,
        "R": 2022, "S": 2023, "T": 2024,
    }

    # Factory encoding (first 3 chars for 12-char, first 2 for 11-char)
    factory_map = {
        "C02": "Foxconn Zhengzhou (China)",
        "C1M": "Foxconn Zhengzhou (China)",
        "C39": "Foxconn Zhengzhou (China)",
        "C7J": "Apple Elk Grove (USA)",
        "CK9": "Foxconn Shenzhen (China)",
        "DKH": "Foxconn Shenzhen (China)",
        "F17": "Foxconn (China)",
        "F4G": "Foxconn Jundiai (Brazil)",
        "FK0": "Foxconn Shenzhen (China)",
        "G4D": "Flextronics (India)",
    }

    result = {
        "serial": serial,
        "manufacturer": "Apple Inc.",
        "serial_length": len(serial),
    }

    prefix = serial[:3]
    if prefix in factory_map:
        result["factory"] = factory_map[prefix]

    if len(serial) == 12:
        year_char = serial[3]
        if year_char in year_map:
            result["approximate_year"] = year_map[year_char]

    return result


# ─────────────────────────────────────────────────────────────────────
# ICCID DECODER
# ─────────────────────────────────────────────────────────────────────

def decode_iccid(iccid):
    """
    Decode carrier and country info from ICCID structure.
    ICCID format is standardized in ITU-T E.118.
    Runs entirely locally - no external query.
    
    Structure: 89 + CC + NIN + SIMNUM + CHECK
      89       = Telecom industry identifier
      CC       = Country code (2-3 digits)
      NIN      = Network identifier
      SIMNUM   = SIM card number
      CHECK    = Luhn check digit
    """
    if not iccid.startswith("89"):
        return None

    country_codes = {
        "1":   "United States / Canada",
        "7":   "Russia / Kazakhstan",
        "20":  "Egypt",
        "27":  "South Africa",
        "30":  "Greece",
        "31":  "Netherlands",
        "32":  "Belgium",
        "33":  "France",
        "34":  "Spain",
        "36":  "Hungary",
        "39":  "Italy",
        "40":  "Romania",
        "41":  "Switzerland",
        "43":  "Austria",
        "44":  "United Kingdom",
        "45":  "Denmark",
        "46":  "Sweden",
        "47":  "Norway",
        "48":  "Poland",
        "49":  "Germany",
        "51":  "Peru",
        "52":  "Mexico",
        "54":  "Argentina",
        "55":  "Brazil",
        "57":  "Colombia",
        "61":  "Australia",
        "62":  "Indonesia",
        "63":  "Philippines",
        "64":  "New Zealand",
        "65":  "Singapore",
        "66":  "Thailand",
        "81":  "Japan",
        "82":  "South Korea",
        "86":  "China",
        "90":  "Turkey",
        "91":  "India",
        "92":  "Pakistan",
        "234": "United Kingdom (T-Mobile/EE)",
        "310": "United States (AT&T)",
        "311": "United States (US Cellular)",
        "312": "United States (regional)",
        "313": "United States (regional)",
        "314": "United States (regional)",
        "315": "United States (regional)",
        "316": "United States (T-Mobile)",
    }

    # Strip the 89 prefix to get MCC
    remainder = iccid[2:]

    # Try 3-digit country code first, then 2-digit, then 1-digit
    # Strip leading zeros for lookup (US country code is "1" not "01")
    country = None
    mcc = None

    for length in (3, 2, 1):
        candidate = remainder[:length]
        stripped = candidate.lstrip("0") or "0"
        for key in ([candidate, stripped] if candidate != stripped else [candidate]):
            if key in country_codes:
                country = country_codes[key]
                mcc = candidate
                break
        if country:
            break

    return {
        "iccid": iccid,
        "industry_identifier": "89 (Telecom)",
        "country_code": mcc,
        "country": country or "Unknown",
        "length": len(iccid),
        "luhn_valid": luhn_check(iccid),
    }


# ─────────────────────────────────────────────────────────────────────
# MAIN ROUTER CLASS
# ─────────────────────────────────────────────────────────────────────

class InputRouter:
    """
    Accepts any input. Identifies it. Routes it.
    Logs everything to evidence journal before processing.
    """

    def __init__(self, journal=None):
        self.journal = journal or EvidenceJournal()

    def route(self, raw_input):
        """
        Main entry point. Takes raw input string.
        Returns detection result with routing instructions.
        
        Args:
            raw_input: String from investigator. Could be anything.
            
        Returns:
            dict: {
                "input": original input,
                "type": detected type,
                "normalized": cleaned/normalized value,
                "route": which module to send to,
                "decoded": any locally-decodable info,
                "confidence": how confident we are in the type detection,
                "journal_hash": SHA-256 hash of this log entry
            }
        """
        value = raw_input.strip()

        # Log to evidence journal immediately
        journal_entry = self.journal.log(
            module="m0_input_router",
            query=f"ROUTE: {value}",
            source="investigator_input",
            response=f"Routing input: {value[:50]}{'...' if len(value) > 50 else ''}"
        )

        # Check if it's a file path
        if os.path.isfile(value):
            return self._route_file(value, journal_entry)

        # Run detection in priority order
        detected = self._detect(value)

        # Log the detection result
        self.journal.log(
            module="m0_input_router",
            query=f"DETECT: {value}",
            source="pattern_matching",
            response=detected
        )

        result = {
            "input":        value,
            "type":         detected["type"],
            "normalized":   detected["normalized"],
            "route":        INPUT_TYPES.get(detected["type"], "UNKNOWN"),
            "decoded":      detected.get("decoded"),
            "confidence":   detected["confidence"],
            "journal_hash": journal_entry["entry_hash"],
        }

        self._print_result(result)
        return result

    def route_multiple(self, inputs):
        """
        Route multiple inputs. Used when investigator has several
        identifiers from the same encounter (multiple phones, SIMs, etc.)
        
        Args:
            inputs: list of raw input strings
            
        Returns:
            list of route results with burner pattern analysis
        """
        results = [self.route(inp) for inp in inputs]

        # Analyze for burner patterns if multiple devices
        device_inputs = [r for r in results if r["type"] in ("IMEI", "SERIAL", "MAC", "ICCID")]

        if len(device_inputs) >= 3:
            pattern = self._analyze_burner_pattern(device_inputs)
            for r in results:
                r["burner_pattern"] = pattern

        return results

    # ─────────────────────────────────────────────────────────────
    # DETECTION LOGIC
    # ─────────────────────────────────────────────────────────────

    def _detect(self, value):
        """
        Run detection in strict priority order.

        Priority order matters:
          1. Email      (@ sign is unambiguous)
          2. IPv4       (dotted decimal, must come before domain)
          3. MAC        (hex pairs with colons, must come BEFORE IPv6)
          4. IPv6       (hex with colons, comes AFTER MAC)
          5. ICCID      (89 prefix + digits, must come BEFORE IMEI)
          6. IMEI       (exactly 15 digits + Luhn)
          7. Phone      (10-15 digits, comes after IMEI/ICCID)
          8. Domain     (dot-separated labels, must come BEFORE serial)
          9. Apple serial (11-12 char specific format)
          10. Generic serial (8-20 alphanumeric, catch-all)
        """
        # Strip common formatting but NOT dots (needed for domain check)
        clean_nodots = re.sub(r"[\s\-\(\)]", "", value)
        # Strip everything for pure numeric checks
        clean_all = re.sub(r"[\s\-\(\)\.]", "", value)

        # ── 1. EMAIL ──────────────────────────────────────────────
        if PATTERN_EMAIL.match(value):
            return {
                "type": "EMAIL",
                "normalized": value.lower(),
                "confidence": 99,
            }

        # ── 2. IPv4 ───────────────────────────────────────────────
        if PATTERN_IPV4.match(value) and validate_ipv4(value):
            return {
                "type": "IPV4",
                "normalized": value,
                "confidence": 99,
            }

        # ── 3. MAC (BEFORE IPv6 - both use hex with colons) ───────
        # MAC is exactly 6 pairs of hex separated by colons or dashes
        # or 12 consecutive hex digits
        mac_colon = re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", value)
        mac_dash  = re.match(r"^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$", value)
        mac_plain = re.match(r"^[0-9a-fA-F]{12}$", clean_all)

        if mac_colon or mac_dash:
            normalized_mac = value.upper().replace("-", ":")
            return {
                "type": "MAC",
                "normalized": normalized_mac,
                "confidence": 99,
                "decoded": {
                    "oui_prefix": normalized_mac[:8],
                    "note": "OUI lookup runs in Module 5 against local IEEE database"
                }
            }

        if mac_plain and len(clean_all) == 12:
            # 12 hex chars with no separators - could be MAC
            # Only treat as MAC if all chars are valid hex
            try:
                int(clean_all, 16)
                normalized_mac = ":".join(
                    clean_all.upper()[i:i+2] for i in range(0, 12, 2)
                )
                return {
                    "type": "MAC",
                    "normalized": normalized_mac,
                    "confidence": 80,  # Lower confidence - ambiguous
                    "decoded": {
                        "oui_prefix": normalized_mac[:8],
                        "note": "OUI lookup runs in Module 5 against local IEEE database"
                    }
                }
            except ValueError:
                pass

        # ── 4. IPv6 (AFTER MAC) ───────────────────────────────────
        if PATTERN_IPV6.match(value):
            return {
                "type": "IPV6",
                "normalized": value.lower(),
                "confidence": 97,
            }

        # ── 5. ICCID (89 prefix, BEFORE IMEI) ────────────────────
        if PATTERN_ICCID.match(clean_all):
            decoded = decode_iccid(clean_all)
            return {
                "type": "ICCID",
                "normalized": clean_all,
                "confidence": 98,
                "decoded": decoded,
            }

        # ── 6. IMEI (15 digits + Luhn) ────────────────────────────
        if PATTERN_IMEI.match(clean_all):
            luhn_valid = luhn_check(clean_all)
            return {
                "type": "IMEI",
                "normalized": clean_all,
                "confidence": 97 if luhn_valid else 60,
                "decoded": {
                    "luhn_valid": luhn_valid,
                    "tac_prefix": clean_all[:8],
                    "note": "TAC lookup runs in Module 5 against local GSMA database"
                }
            }

        # ── 7. PHONE (AFTER IMEI/ICCID) ──────────────────────────
        digits_only = re.sub(r"\D", "", value)
        if PATTERN_PHONE.match(value) and 10 <= len(digits_only) <= 15:
            if not PATTERN_IMEI.match(digits_only) and not PATTERN_ICCID.match(digits_only):
                return {
                    "type": "PHONE",
                    "normalized": digits_only,
                    "confidence": 85,
                    "decoded": {
                        "note": "Carrier lookup runs in Module 5 via FCC NANPA database"
                    }
                }

        # ── 8. DOMAIN (BEFORE serial - dots make it unambiguous) ──
        # Use original value with dots intact
        if PATTERN_DOMAIN.match(value):
            return {
                "type": "DOMAIN",
                "normalized": value.lower(),
                "confidence": 98,
            }

        # ── 9. APPLE SERIAL (specific format, 11-12 chars) ────────
        if is_apple_serial(clean_all.upper()):
            decoded = decode_apple_serial(clean_all.upper())
            return {
                "type": "SERIAL",
                "normalized": clean_all.upper(),
                "confidence": 88,
                "decoded": decoded,
            }

        # ── 10. GENERIC SERIAL (catch-all) ────────────────────────
        if PATTERN_SERIAL.match(clean_all.upper()) and 8 <= len(clean_all) <= 20:
            return {
                "type": "SERIAL",
                "normalized": clean_all.upper(),
                "confidence": 70,
                "decoded": {
                    "note": "Serial cross-referenced in Module 5 against FCC and stolen device databases"
                }
            }

        # ── UNKNOWN ───────────────────────────────────────────────
        return {
            "type": "UNKNOWN",
            "normalized": value,
            "confidence": 0,
        }

    def _route_file(self, filepath, journal_entry):
        """
        Parse a log file for all recognizable identifier types.
        Extract each one and route it individually.
        """
        self.journal.log(
            module="m0_input_router",
            query=f"PARSE_FILE: {filepath}",
            source="file_system",
            response=f"Parsing log file for identifiers"
        )

        found = []

        with open(filepath, "r", errors="replace") as f:
            content = f.read()

        # Find all potential identifiers in the file
        # IPs
        for ip in re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", content):
            if validate_ipv4(ip):
                found.append(ip)

        # Emails
        for email in re.findall(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", content):
            found.append(email)

        # Domains
        for domain in re.findall(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b", content):
            if not validate_ipv4(domain):
                found.append(domain)

        # IMEIs
        for imei in re.findall(r"\b\d{15}\b", content):
            if luhn_check(imei):
                found.append(imei)

        # ICCIDs
        for iccid in re.findall(r"\b89\d{17,18}\b", content):
            found.append(iccid)

        # MACs
        for mac in re.findall(r"\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b", content):
            found.append(mac)

        self.journal.log(
            module="m0_input_router",
            query=f"FILE_RESULTS: {filepath}",
            source="pattern_extraction",
            response=f"Found {len(found)} identifiers in file"
        )

        results = [self.route(identifier) for identifier in set(found)]

        return {
            "input": filepath,
            "type": "LOG_FILE",
            "normalized": filepath,
            "route": INPUT_TYPES["LOG_FILE"],
            "decoded": {
                "identifiers_found": len(results),
                "breakdown": {t: sum(1 for r in results if r["type"] == t)
                             for t in set(r["type"] for r in results)}
            },
            "confidence": 99,
            "extracted_results": results,
            "journal_hash": journal_entry["entry_hash"],
        }

    def _analyze_burner_pattern(self, device_results):
        """
        When multiple devices are encountered together, analyze for
        burner phone network patterns.

        Signals:
          - Same OUI prefix (same manufacturer, possibly same batch)
          - Sequential or near-sequential serials (purchased together)
          - All same device type (identical hardware)

        Returns:
          dict: Pattern classification and signals found

        IMPORTANT: This is a confidence modifier, not proof.
        A small business buying 10 phones shows identical patterns.
        The investigator must evaluate in context.
        """
        signals = []
        pattern = "INDIVIDUAL"

        # Extract OUI prefixes from MAC addresses
        macs = [r["normalized"] for r in device_results if r["type"] == "MAC"]
        if macs:
            oui_prefixes = [m[:8] for m in macs]
            if len(set(oui_prefixes)) == 1 and len(oui_prefixes) >= 3:
                signals.append("IDENTICAL_OUI: All devices same manufacturer batch")

        # Extract IMEI TAC codes
        imeis = [r["normalized"] for r in device_results if r["type"] == "IMEI"]
        if imeis:
            tac_codes = [i[:8] for i in imeis]
            if len(set(tac_codes)) == 1 and len(tac_codes) >= 3:
                signals.append("IDENTICAL_TAC: All devices exact same model")

        # Check for sequential serials
        serials = [r["normalized"] for r in device_results if r["type"] == "SERIAL"]
        if len(serials) >= 3:
            # Sort and check gaps
            try:
                numeric_parts = []
                for s in serials:
                    nums = re.findall(r"\d+", s)
                    if nums:
                        numeric_parts.append(int(nums[-1]))

                if len(numeric_parts) >= 3:
                    numeric_parts.sort()
                    gaps = [numeric_parts[i+1] - numeric_parts[i]
                           for i in range(len(numeric_parts)-1)]
                    avg_gap = sum(gaps) / len(gaps)

                    if avg_gap <= 5:
                        signals.append(f"SEQUENTIAL_SERIALS: Average gap {avg_gap:.1f} (purchased together)")
            except (ValueError, ZeroDivisionError):
                pass

        # Classify based on signals
        if len(signals) >= 3:
            pattern = "BURNER_NETWORK"
        elif len(signals) >= 2:
            pattern = "SUSPICIOUS"
        elif len(signals) == 1:
            pattern = "POSSIBLE"
        else:
            pattern = "INDIVIDUAL"

        return {
            "pattern": pattern,
            "signals": signals,
            "devices_analyzed": len(device_results),
            "investigator_note": (
                "Pattern is investigative signal only. "
                "Legitimate businesses buying multiple phones "
                "show identical patterns. Evaluate in full context."
            )
        }

    # ─────────────────────────────────────────────────────────────
    # OUTPUT
    # ─────────────────────────────────────────────────────────────

    def _print_result(self, result):
        """Print detection result to console."""
        confidence_bar = "█" * (result["confidence"] // 10) + "░" * (10 - result["confidence"] // 10)

        print(f"\n[CTF/M0] Input detected")
        print(f"  Type:       {result['type']}")
        print(f"  Normalized: {result['normalized']}")
        print(f"  Route:      {result['route']}")
        print(f"  Confidence: {result['confidence']}% [{confidence_bar}]")

        if result.get("decoded"):
            print(f"  Decoded:")
            for k, v in result["decoded"].items():
                print(f"    {k}: {v}")

        print(f"  Evidence:   {result['journal_hash'][:16]}...")


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 0 Input Router Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        router = InputRouter(journal=journal)

        test_inputs = [
            ("Domain",        "ssiloc.com"),
            ("IPv4",          "192.0.2.88"),
            ("Email",         "suspect@email.com"),
            ("Phone",         "+1 (555) 123-4567"),
            ("IMEI",          "356938035643809"),
            ("ICCID",         "8901260123456789013"),
            ("MAC",           "AA:BB:CC:DD:EE:FF"),
            ("Apple Serial",  "C02XG2JDJGH5"),
            ("Unknown",       "???notanything???"),
        ]

        for label, value in test_inputs:
            print(f"\n{'─' * 40}")
            print(f"Testing: {label} → '{value}'")
            result = router.route(value)
            assert result["type"] != "UNKNOWN" or label == "Unknown", \
                f"Failed to detect {label}: got {result['type']}"

        # Test multiple inputs (burner pattern)
        print(f"\n{'─' * 40}")
        print("Testing burner pattern detection (3 same-model IMEIs)...")
        multi_results = router.route_multiple([
            "356938035643809",
            "356938035643817",
            "356938035643825",
        ])
        if multi_results[0].get("burner_pattern"):
            print(f"  Pattern: {multi_results[0]['burner_pattern']['pattern']}")
            for signal in multi_results[0]['burner_pattern']['signals']:
                print(f"  Signal: {signal}")

        print(f"\n{'=' * 60}")
        print(f"Module 0 self-test complete.")
        v = journal.verify()
        print(f"Evidence chain: {v['entries_verified']} entries, valid={v['valid']}")
        print("=" * 60)
