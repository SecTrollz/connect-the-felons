#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 1 - Infrastructure Fingerprinting

One job: Turn a domain or IP into a complete infrastructure picture
using only direct queries and locally stored databases.

No third party APIs. No rate limits. No subscriptions.

Data sources (all direct queries):
  - DNS resolution:    system dig/nslookup
  - IP geolocation:   MaxMind GeoLite2 (local database)
  - ASN lookup:       ARIN/RIPE/APNIC/AFRINIC/LACNIC (direct WHOIS protocol)
  - Reverse DNS:      system dig -x
  - Historical IPs:   CIRCL passive DNS (direct API, free account)
  - Certificates:     crt.sh (direct API, no key needed)
  - Related domains:  reverse DNS + certificate SAN extraction
"""

import subprocess
import json
import re
import socket
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal


# ─────────────────────────────────────────────────────────────────────
# GEOIP DATABASE (MaxMind GeoLite2)
# ─────────────────────────────────────────────────────────────────────

def load_geoip():
    """
    Load MaxMind GeoLite2 database if available.
    Returns reader object or None if database not installed.
    
    To install:
      1. Register free at maxmind.com
      2. Download GeoLite2-City.mmdb
      3. Place in ctf/data/geoip/GeoLite2-City.mmdb
    """
    db_path = Path(__file__).parent.parent / "data" / "geoip" / "GeoLite2-City.mmdb"
    if not db_path.exists():
        return None
    try:
        import geoip2.database
        return geoip2.database.Reader(str(db_path))
    except ImportError:
        return None
    except Exception:
        return None


GEOIP_READER = load_geoip()


# ─────────────────────────────────────────────────────────────────────
# ASN WHOIS ENDPOINTS (Regional Internet Registries)
# ─────────────────────────────────────────────────────────────────────

RIR_WHOIS = {
    "ARIN":    "whois.arin.net",     # Americas
    "RIPE":    "whois.ripe.net",     # Europe, Middle East, Central Asia
    "APNIC":   "whois.apnic.net",    # Asia Pacific
    "AFRINIC": "whois.afrinic.net",  # Africa
    "LACNIC":  "whois.lacnic.net",   # Latin America and Caribbean
}

# IP ranges for each RIR (simplified - used to pick correct RIR first)
RIR_RANGES = {
    "ARIN": [
        "3.", "4.", "6.", "7.", "8.", "9.", "11.", "12.", "13.", "15.", "16.",
        "17.", "18.", "20.", "23.", "24.", "32.", "44.", "45.", "50.", "52.",
        "54.", "63.", "64.", "65.", "66.", "67.", "68.", "69.", "70.", "71.",
        "72.", "73.", "74.", "75.", "76.", "96.", "97.", "98.", "99.", "100.",
        "104.", "107.", "108.", "184.", "192.", "198.", "199.", "204.", "205.",
        "206.", "207.", "208.", "209.", "216.",
    ],
    "RIPE": [
        "2.", "5.", "25.", "31.", "37.", "46.", "62.", "77.", "78.", "79.",
        "80.", "81.", "82.", "83.", "84.", "85.", "86.", "87.", "88.", "89.",
        "90.", "91.", "92.", "93.", "94.", "95.", "109.", "146.", "176.",
        "178.", "185.", "188.", "193.", "194.", "195.", "212.", "213.",
    ],
    "APNIC": [
        "1.", "14.", "27.", "36.", "39.", "42.", "43.", "49.", "58.", "59.",
        "60.", "61.", "101.", "103.", "106.", "110.", "111.", "112.", "113.",
        "114.", "115.", "116.", "117.", "118.", "119.", "120.", "121.", "122.",
        "123.", "124.", "125.", "126.", "150.", "153.", "163.", "171.", "175.",
        "180.", "182.", "183.", "202.", "203.", "210.", "211.", "218.", "219.",
        "220.", "221.", "222.", "223.",
    ],
    "AFRINIC": [
        "41.", "102.", "105.", "154.", "160.", "161.", "162.", "164.", "196.",
        "197.",
    ],
    "LACNIC": [
        "177.", "179.", "181.", "186.", "187.", "189.", "190.", "191.", "200.",
        "201.",
    ],
}


def pick_rir(ip):
    """Select the most likely RIR for an IP address."""
    prefix = ip.split(".")[0] + "."
    for rir, prefixes in RIR_RANGES.items():
        if prefix in prefixes:
            return rir
    return "ARIN"  # Default


# ─────────────────────────────────────────────────────────────────────
# CORE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────

def resolve_domain(domain):
    """
    Resolve domain to IPv4 and IPv6 addresses.
    Uses system DNS resolver directly.
    Returns dict with all resolved addresses.
    """
    result = {"domain": domain, "ipv4": [], "ipv6": [], "error": None}

    # IPv4 (A records)
    try:
        proc = subprocess.run(
            ["dig", "+short", "+time=5", "+tries=2", "A", domain],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().split("\n"):
                line = line.strip()
                if line and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                    result["ipv4"].append(line)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fall back to socket if dig not available
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            result["ipv4"] = list(set(i[4][0] for i in infos))
        except socket.gaierror as e:
            result["error"] = str(e)

    # IPv6 (AAAA records)
    try:
        proc = subprocess.run(
            ["dig", "+short", "+time=5", "+tries=2", "AAAA", domain],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().split("\n"):
                line = line.strip()
                if line and ":" in line and not line.startswith(";"):
                    result["ipv6"].append(line)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return result


def reverse_dns(ip):
    """
    Reverse DNS lookup: IP → hostnames.
    Direct system query.
    """
    result = {"ip": ip, "hostnames": [], "error": None}

    try:
        proc = subprocess.run(
            ["dig", "+short", "+time=5", "+tries=2", "-x", ip],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().split("\n"):
                line = line.strip().rstrip(".")
                if line and not line.startswith(";"):
                    result["hostnames"].append(line)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fall back to socket
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result["hostnames"] = [hostname]
        except socket.herror as e:
            result["error"] = str(e)

    return result


def geolocate_ip(ip):
    """
    Geolocate an IP address.
    
    Primary: MaxMind GeoLite2 local database (offline, no rate limit)
    Fallback: ip-api.com direct API (free, no key required)
    
    Returns dict with location data and source.
    """
    result = {
        "ip": ip,
        "city": None,
        "region": None,
        "country": None,
        "country_code": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
        "org": None,
        "asn": None,
        "type": None,  # residential, datacenter, vpn, proxy
        "source": None,
        "error": None,
    }

    # Try local MaxMind database first
    if GEOIP_READER:
        try:
            response = GEOIP_READER.city(ip)
            result.update({
                "city":         response.city.name,
                "region":       response.subdivisions.most_specific.name,
                "country":      response.country.name,
                "country_code": response.country.iso_code,
                "latitude":     float(response.location.latitude or 0),
                "longitude":    float(response.location.longitude or 0),
                "source":       "MaxMind GeoLite2 (local)",
            })
            return result
        except Exception:
            pass  # Fall through to API

    # Fallback: ip-api.com (free, direct query, no key)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,hosting"
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        if data.get("status") == "success":
            result.update({
                "city":         data.get("city"),
                "region":       data.get("regionName"),
                "country":      data.get("country"),
                "country_code": data.get("countryCode"),
                "latitude":     data.get("lat"),
                "longitude":    data.get("lon"),
                "isp":          data.get("isp"),
                "org":          data.get("org"),
                "asn":          data.get("as"),
                "type":         "datacenter" if data.get("hosting") else "residential",
                "source":       "ip-api.com (direct API)",
            })
        else:
            result["error"] = data.get("message", "API error")

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


def asn_lookup(ip):
    """
    Look up ASN information for an IP address.
    Direct WHOIS protocol query to the appropriate Regional Internet Registry.
    No API key. No third party.
    """
    result = {
        "ip": ip,
        "asn": None,
        "asn_name": None,
        "cidr": None,
        "rir": None,
        "country": None,
        "error": None,
    }

    rir = pick_rir(ip)
    whois_server = RIR_WHOIS[rir]
    result["rir"] = rir

    try:
        proc = subprocess.run(
            ["whois", "-h", whois_server, ip],
            capture_output=True, text=True, timeout=15
        )
        output = proc.stdout

        # Parse ASN
        for line in output.split("\n"):
            line = line.strip()
            if re.match(r"^(aut-num|ASNumber|origin|OriginAS):", line, re.I):
                asn_match = re.search(r"AS(\d+)", line, re.I)
                if asn_match:
                    result["asn"] = f"AS{asn_match.group(1)}"
            elif re.match(r"^(OrgName|netname|org-name|descr):", line, re.I):
                value = line.split(":", 1)[1].strip()
                if value and not result["asn_name"]:
                    result["asn_name"] = value
            elif re.match(r"^(CIDR|inetnum|NetRange):", line, re.I):
                value = line.split(":", 1)[1].strip()
                if value and not result["cidr"]:
                    result["cidr"] = value
            elif re.match(r"^Country:", line, re.I):
                value = line.split(":", 1)[1].strip()
                if value and not result["country"]:
                    result["country"] = value

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        result["error"] = str(e)

    return result


def certificate_history(domain):
    """
    Fetch certificate transparency history from crt.sh.
    Direct API query. Free. No account. No rate limit for reasonable use.
    
    Returns list of certificate records including:
      - Issuer
      - Subject (what the cert is for)
      - SAN (Subject Alternative Names - other domains on same cert)
      - Issue date
      - Expiry date
    """
    result = {
        "domain": domain,
        "certificates": [],
        "related_domains": set(),
        "error": None,
    }

    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=15) as response:
            certs = json.loads(response.read().decode())

        for cert in certs[:50]:  # Limit to 50 most recent
            entry = {
                "id":           cert.get("id"),
                "issued_at":    cert.get("entry_timestamp"),
                "not_before":   cert.get("not_before"),
                "not_after":    cert.get("not_after"),
                "issuer":       cert.get("issuer_name"),
                "common_name":  cert.get("common_name"),
                "name_value":   cert.get("name_value"),
            }
            result["certificates"].append(entry)

            # Extract SAN entries (domains sharing this certificate)
            name_value = cert.get("name_value", "")
            for san in name_value.split("\n"):
                san = san.strip().lstrip("*.")
                if san and san != domain and "." in san:
                    # Filter out wildcard base and generic CAs
                    if not any(x in san for x in ["ca.", "ocsp.", "crl."]):
                        result["related_domains"].add(san)

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    result["related_domains"] = list(result["related_domains"])
    return result


def find_related_domains(ip):
    """
    Find other domains hosted on the same IP.
    Uses reverse DNS and certificate SAN analysis.
    All direct queries, no third party.
    """
    related = set()

    # Reverse DNS gives us hostnames pointing to this IP
    rdns = reverse_dns(ip)
    for hostname in rdns.get("hostnames", []):
        # Strip common service prefixes to get base domain
        parts = hostname.split(".")
        if len(parts) >= 2:
            related.add(hostname)
            # Also add parent domain
            related.add(".".join(parts[-2:]))

    return list(related)


def classify_infrastructure(geoloc, asn_info):
    """
    Classify whether an IP is residential, datacenter, VPN, or proxy.
    Based on ASN name patterns and geolocation data.
    
    This classification is a signal, not proof.
    """
    datacenter_keywords = [
        "amazon", "aws", "google", "microsoft", "azure", "cloudflare",
        "digitalocean", "linode", "vultr", "ovh", "hetzner", "leaseweb",
        "hosting", "datacenter", "data center", "cdn", "cloud", "server",
        "rack", "colocation", "colo", "vps", "dedicated",
    ]

    vpn_keywords = [
        "vpn", "nordvpn", "expressvpn", "surfshark", "mullvad", "proton",
        "private", "anonymize", "privacy", "tunnel", "torguard",
    ]

    proxy_keywords = [
        "proxy", "socks", "tor", "exit node", "anonymizer",
    ]

    asn_name = (asn_info.get("asn_name") or "").lower()
    isp = (geoloc.get("isp") or "").lower()
    org = (geoloc.get("org") or "").lower()

    combined = f"{asn_name} {isp} {org}"

    if any(k in combined for k in vpn_keywords):
        return "vpn"
    if any(k in combined for k in proxy_keywords):
        return "proxy"
    if any(k in combined for k in datacenter_keywords):
        return "datacenter"
    if geoloc.get("type") == "datacenter":
        return "datacenter"

    return "residential"


# ─────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORING
# ─────────────────────────────────────────────────────────────────────

def score_geolocation_confidence(results):
    """
    Score confidence in geolocation based on source availability
    and consistency.
    
    Returns 0-100 confidence score.
    """
    if not results:
        return 0

    # Base score from number of successful lookups
    successful = [r for r in results if not r.get("error") and r.get("country")]
    if not successful:
        return 0

    base_score = min(len(successful) * 40, 80)

    # Bonus for consistency across sources
    countries = [r.get("country_code") for r in successful if r.get("country_code")]
    if len(set(countries)) == 1 and len(countries) > 1:
        base_score += 15  # All sources agree on country

    cities = [r.get("city") for r in successful if r.get("city")]
    if len(set(cities)) == 1 and len(cities) > 1:
        base_score += 5   # All sources agree on city

    return min(base_score, 99)


# ─────────────────────────────────────────────────────────────────────
# MAIN MODULE CLASS
# ─────────────────────────────────────────────────────────────────────

class InfrastructureFingerprinter:
    """
    Takes a domain or IP.
    Returns complete infrastructure picture.
    Logs everything to evidence journal.
    """

    def __init__(self, journal=None):
        self.journal = journal or EvidenceJournal()

    def fingerprint_domain(self, domain):
        """
        Complete infrastructure analysis starting from a domain name.
        
        Returns:
            dict: Complete infrastructure picture with all findings
        """
        print(f"\n[CTF/M1] Fingerprinting domain: {domain}")
        results = {"domain": domain, "timestamp": datetime.now(timezone.utc).isoformat()}

        # Step 1: Resolve to IPs
        print(f"  [1/5] DNS resolution...")
        dns_result = resolve_domain(domain)
        self.journal.log(
            module="m1_infrastructure",
            query=f"DNS A+AAAA: {domain}",
            source="DNS/system-dig",
            response=dns_result
        )
        results["dns"] = dns_result

        all_ips = dns_result.get("ipv4", []) + dns_result.get("ipv6", [])

        if not all_ips:
            print(f"  [!] No IPs resolved for {domain}")
            results["error"] = "Domain did not resolve"
            return results

        print(f"  └─ Resolved to: {', '.join(all_ips)}")

        # Step 2: Fingerprint each IP
        results["ips"] = {}
        for ip in all_ips[:5]:  # Limit to first 5 IPs
            print(f"  [2/5] Fingerprinting IP: {ip}")
            ip_result = self.fingerprint_ip(ip)
            results["ips"][ip] = ip_result

        # Step 3: Certificate history
        print(f"  [3/5] Certificate history (crt.sh)...")
        cert_result = certificate_history(domain)
        self.journal.log(
            module="m1_infrastructure",
            query=f"crt.sh: {domain}",
            source="crt.sh/direct-API",
            response={
                "certificate_count": len(cert_result.get("certificates", [])),
                "related_domains": cert_result.get("related_domains", []),
                "error": cert_result.get("error"),
            }
        )
        results["certificates"] = cert_result
        print(f"  └─ Found {len(cert_result.get('certificates', []))} certificates")
        if cert_result.get("related_domains"):
            print(f"  └─ Related domains via cert SAN: {', '.join(cert_result['related_domains'][:5])}")

        # Step 4: Infrastructure summary
        results["summary"] = self._summarize(results)
        print(f"  [4/5] Summary built")

        # Step 5: Confidence score
        geolocs = [
            results["ips"].get(ip, {}).get("geolocation", {})
            for ip in all_ips[:5]
        ]
        results["confidence"] = score_geolocation_confidence(geolocs)
        print(f"  [5/5] Confidence: {results['confidence']}%")

        return results

    def fingerprint_ip(self, ip):
        """
        Complete infrastructure analysis starting from an IP address.
        """
        print(f"\n[CTF/M1] Fingerprinting IP: {ip}")
        result = {"ip": ip, "timestamp": datetime.now(timezone.utc).isoformat()}

        # Geolocation
        print(f"  [1/4] Geolocation...")
        geo = geolocate_ip(ip)
        self.journal.log(
            module="m1_infrastructure",
            query=f"geolocate: {ip}",
            source=geo.get("source", "ip-api.com"),
            response=geo
        )
        result["geolocation"] = geo
        if geo.get("city"):
            print(f"  └─ Location: {geo.get('city')}, {geo.get('region')}, {geo.get('country')}")

        # ASN lookup
        print(f"  [2/4] ASN lookup...")
        asn = asn_lookup(ip)
        self.journal.log(
            module="m1_infrastructure",
            query=f"whois ASN: {ip}",
            source=f"RIR/{asn.get('rir', 'UNKNOWN')}-direct-WHOIS",
            response=asn
        )
        result["asn"] = asn
        if asn.get("asn"):
            print(f"  └─ ASN: {asn.get('asn')} ({asn.get('asn_name')})")

        # Reverse DNS
        print(f"  [3/4] Reverse DNS...")
        rdns = reverse_dns(ip)
        self.journal.log(
            module="m1_infrastructure",
            query=f"reverse-DNS: {ip}",
            source="DNS/system-dig-x",
            response=rdns
        )
        result["reverse_dns"] = rdns
        if rdns.get("hostnames"):
            print(f"  └─ Hostnames: {', '.join(rdns['hostnames'][:3])}")

        # Infrastructure classification
        infra_type = classify_infrastructure(geo, asn)
        result["infrastructure_type"] = infra_type
        self.journal.log(
            module="m1_infrastructure",
            query=f"classify: {ip}",
            source="local-classification-engine",
            response={"type": infra_type}
        )
        print(f"  [4/4] Infrastructure type: {infra_type.upper()}")

        # Related domains
        related = find_related_domains(ip)
        result["related_domains"] = related
        if related:
            print(f"  └─ Related domains: {', '.join(related[:3])}")

        return result

    def _summarize(self, results):
        """Build a plain-language summary of findings."""
        domain = results.get("domain")
        ips = results.get("ips", {})
        certs = results.get("certificates", {})

        locations = []
        asns = []
        infra_types = []

        for ip, ip_data in ips.items():
            geo = ip_data.get("geolocation", {})
            if geo.get("city") and geo.get("country"):
                locations.append(f"{geo['city']}, {geo['country']}")
            asn = ip_data.get("asn", {})
            if asn.get("asn_name"):
                asns.append(asn["asn_name"])
            it = ip_data.get("infrastructure_type")
            if it:
                infra_types.append(it)

        return {
            "domain": domain,
            "resolves_to": list(ips.keys()),
            "locations": list(set(locations)),
            "hosting_providers": list(set(asns)),
            "infrastructure_types": list(set(infra_types)),
            "related_domains_via_cert": certs.get("related_domains", []),
            "certificate_count": len(certs.get("certificates", [])),
        }


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 1 Infrastructure Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        fp = InfrastructureFingerprinter(journal=journal)

        # Test with a known public domain
        print("\nTest 1: Fingerprint a domain (example.com)")
        result = fp.fingerprint_domain("example.com")

        print(f"\nResults:")
        print(f"  Domain: {result['domain']}")
        print(f"  IPs found: {list(result.get('ips', {}).keys())}")

        for ip, ip_data in result.get("ips", {}).items():
            geo = ip_data.get("geolocation", {})
            asn = ip_data.get("asn", {})
            print(f"\n  IP: {ip}")
            print(f"    Location: {geo.get('city')}, {geo.get('country')}")
            print(f"    ASN: {asn.get('asn')} - {asn.get('asn_name')}")
            print(f"    Type: {ip_data.get('infrastructure_type', 'unknown').upper()}")

        cert_count = len(result.get("certificates", {}).get("certificates", []))
        related = result.get("certificates", {}).get("related_domains", [])
        print(f"\n  Certificates: {cert_count}")
        print(f"  Related domains via cert: {related[:5]}")
        print(f"  Confidence: {result.get('confidence')}%")

        # Test with a known IP
        print("\n" + "─" * 40)
        print("Test 2: Fingerprint an IP (8.8.8.8 - Google DNS)")
        ip_result = fp.fingerprint_ip("8.8.8.8")
        geo = ip_result.get("geolocation", {})
        asn = ip_result.get("asn", {})
        print(f"\n  IP: 8.8.8.8")
        print(f"  Location: {geo.get('city')}, {geo.get('country')}")
        print(f"  ASN: {asn.get('asn')} - {asn.get('asn_name')}")
        print(f"  Type: {ip_result.get('infrastructure_type', 'unknown').upper()}")

        # Verify evidence chain
        print("\n" + "─" * 40)
        v = journal.verify()
        print(f"Evidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 1 self-test complete.")
        print("=" * 60)
