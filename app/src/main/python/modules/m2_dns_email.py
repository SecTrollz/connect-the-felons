#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 2 - Email & DNS Forensics

One job: Extract every piece of identity information from a domain's
public records. Who registered it. Who controls its email. What
certificates have been issued. What the DNS history looks like.

Data sources (all direct queries, no third parties):
  - WHOIS:          python-whois library → direct registry query
  - DNS records:    dnspython → system resolver
  - Certificates:   crt.sh direct API (public certificate transparency log)
  - WHOIS history:  archive.org Wayback CDX API (public)
  - Email auth:     SPF, DKIM, DMARC via direct DNS TXT queries
  - Reputation:     Spamhaus ZEN via DNS (no API key needed)
                    URLhaus direct API (free, no key)
"""

import json
import re
import sys
import os
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# dnspython for DNS queries
try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# python-whois for WHOIS queries
try:
    import whois as pythonwhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal


# ─────────────────────────────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────────────────────────────

def whois_lookup(domain):
    """
    WHOIS lookup on a domain.
    Uses python-whois library for direct registry query.
    
    Returns normalized dict with all registrant fields.
    """
    result = {
        "domain":           domain,
        "registrant_name":  None,
        "registrant_email": None,
        "registrant_phone": None,
        "registrant_org":   None,
        "registrant_addr":  None,
        "registrar":        None,
        "created":          None,
        "updated":          None,
        "expires":          None,
        "nameservers":      [],
        "status":           [],
        "privacy_protected": False,
        "raw":              None,
        "error":            None,
    }

    if not WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed"
        return result

    try:
        w = pythonwhois.whois(domain)

        # Normalize fields - python-whois returns various formats
        result["registrant_name"]  = _first(w.get("name"))
        result["registrant_email"] = _first(w.get("emails"))
        result["registrant_org"]   = _first(w.get("org"))
        result["registrar"]        = _first(w.get("registrar"))
        result["created"]          = _normalize_date(w.get("creation_date"))
        result["updated"]          = _normalize_date(w.get("updated_date"))
        result["expires"]          = _normalize_date(w.get("expiration_date"))
        result["status"]           = _as_list(w.get("status"))
        result["raw"]              = w.text if hasattr(w, "text") else str(w)

        # Nameservers
        ns = w.get("name_servers", [])
        if isinstance(ns, list):
            result["nameservers"] = [n.lower().rstrip(".") for n in ns]
        elif isinstance(ns, str):
            result["nameservers"] = [ns.lower().rstrip(".")]

        # Privacy detection - common WHOIS privacy service indicators
        privacy_indicators = [
            "whoisguard", "privacy", "proxy", "redacted", "domains by proxy",
            "perfect privacy", "namecheap", "godaddy", "protect", "shield",
            "withheld", "registrant redacted", "data protected",
        ]
        combined = " ".join(filter(None, [
            result["registrant_name"],
            result["registrant_email"],
            result["registrant_org"],
        ])).lower()

        result["privacy_protected"] = any(p in combined for p in privacy_indicators)

    except Exception as e:
        result["error"] = str(e)

    return result


def whois_history(domain):
    """
    Historical WHOIS snapshots from archive.org.
    Direct Wayback CDX API query. Free. No account needed.
    
    Shows when registrant information changed over time.
    This is often where you catch ownership transfers.
    """
    result = {
        "domain":    domain,
        "snapshots": [],
        "error":     None,
    }

    try:
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=whois.{domain}&output=json&limit=20&fl=timestamp,statuscode"
            f"&filter=statuscode:200&collapse=timestamp:6"
        )
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        for row in data[1:]:  # Skip header row
            if len(row) >= 2:
                ts = row[0]
                result["snapshots"].append({
                    "timestamp": ts,
                    "url": f"https://web.archive.org/web/{ts}/https://whois.{domain}",
                    "formatted": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}",
                })

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# DNS RECORDS
# ─────────────────────────────────────────────────────────────────────

def mx_records(domain):
    """
    MX record lookup. Shows which mail servers handle email for this domain.
    Tells us who the email provider is (Google Workspace, Microsoft 365,
    Proofpoint, custom mail server, etc.)
    """
    result = {
        "domain":   domain,
        "records":  [],
        "provider": None,
        "error":    None,
    }

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=10)
        records = []
        for rdata in sorted(answers, key=lambda x: x.preference):
            records.append({
                "priority": rdata.preference,
                "server":   str(rdata.exchange).rstrip("."),
            })
        result["records"] = records
        result["provider"] = _identify_mail_provider(records)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["error"] = "No MX records found"
    except dns.resolver.Timeout:
        result["error"] = "DNS timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def spf_record(domain):
    """
    SPF (Sender Policy Framework) lookup.
    Tells us which IP addresses/domains are authorized to send
    email from this domain. Often reveals cloud infrastructure.
    
    No SPF = domain likely not used for legitimate email.
    """
    result = {
        "domain":      domain,
        "record":      None,
        "authorized":  [],
        "mechanisms":  [],
        "policy":      None,
        "error":       None,
    }

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=10)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                result["record"] = txt

                # Parse mechanisms
                parts = txt.split()
                for part in parts[1:]:
                    if part.startswith("include:"):
                        result["authorized"].append(part[8:])
                        result["mechanisms"].append({"type": "include", "value": part[8:]})
                    elif part.startswith("ip4:"):
                        result["mechanisms"].append({"type": "ip4", "value": part[4:]})
                    elif part.startswith("ip6:"):
                        result["mechanisms"].append({"type": "ip6", "value": part[4:]})
                    elif part.startswith("a:"):
                        result["mechanisms"].append({"type": "a", "value": part[2:]})
                    elif part == "a":
                        result["mechanisms"].append({"type": "a", "value": domain})
                    elif part == "mx":
                        result["mechanisms"].append({"type": "mx", "value": domain})
                    elif part in ("~all", "-all", "+all", "?all"):
                        result["policy"] = part

                break  # Only one SPF record should exist

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["error"] = "No TXT/SPF records found"
    except dns.resolver.Timeout:
        result["error"] = "DNS timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def dmarc_record(domain):
    """
    DMARC lookup at _dmarc.domain.com
    
    DMARC tells us:
      - Does this domain enforce email authentication?
      - Where do failure reports go? (the rua/ruf addresses reveal who manages email)
      - How strict is their policy? (none/quarantine/reject)
    
    No DMARC = hastily set up domain, likely not a professional organization.
    DMARC p=reject = well-managed org that cares about email security.
    """
    result = {
        "domain":          domain,
        "record":          None,
        "policy":          None,
        "subdomain_policy": None,
        "pct":             100,
        "report_addresses": [],
        "forensic_addresses": [],
        "error":           None,
    }

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=10)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=DMARC1"):
                result["record"] = txt

                parts = dict(
                    part.split("=", 1)
                    for part in txt.split(";")
                    if "=" in part
                )

                result["policy"]           = parts.get("p", "none")
                result["subdomain_policy"] = parts.get("sp")
                result["pct"]             = int(parts.get("pct", 100))

                # Report addresses (who receives DMARC reports)
                if "rua" in parts:
                    for addr in parts["rua"].split(","):
                        result["report_addresses"].append(addr.strip().replace("mailto:", ""))

                if "ruf" in parts:
                    for addr in parts["ruf"].split(","):
                        result["forensic_addresses"].append(addr.strip().replace("mailto:", ""))

                break

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["error"] = "No DMARC record found"
    except dns.resolver.Timeout:
        result["error"] = "DNS timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def dkim_selectors(domain):
    """
    Check common DKIM selectors for this domain.
    DKIM keys are published at {selector}._domainkey.{domain}
    
    The selector name often reveals which email provider is in use.
    Google uses 'google', Microsoft uses 'selector1'/'selector2',
    Mailchimp uses 'k1', etc.
    """
    result = {
        "domain":    domain,
        "found":     [],
        "providers": [],
        "error":     None,
    }

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    # Common DKIM selectors by provider
    common_selectors = {
        "google":    "Google Workspace",
        "google2":   "Google Workspace",
        "selector1": "Microsoft 365",
        "selector2": "Microsoft 365",
        "k1":        "Mailchimp",
        "k2":        "Mailchimp",
        "s1":        "Sendgrid",
        "s2":        "Sendgrid",
        "mandrill":  "Mailchimp Mandrill",
        "protonmail":"ProtonMail",
        "mail":      "Generic",
        "default":   "Generic",
        "dkim":      "Generic",
        "email":     "Generic",
    }

    providers_found = set()

    for selector, provider in common_selectors.items():
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=5)
            result["found"].append(selector)
            providers_found.add(provider)
        except Exception:
            continue

    result["providers"] = list(providers_found)
    return result


# ─────────────────────────────────────────────────────────────────────
# CERTIFICATE HISTORY
# ─────────────────────────────────────────────────────────────────────

def certificate_history(domain):
    """
    Certificate transparency log query via crt.sh.
    Free. Direct API. No account needed.
    
    SSL certificates are logged publicly by CA/Browser Forum requirement.
    Every certificate issued for a domain is public record.
    
    What we learn:
      - When was this domain first secured? (earliest cert date)
      - What other domains share certificates with this one?
        (the SAN list reveals infrastructure relationships)
      - Which Certificate Authority was used?
        (self-signed = hidden, Let's Encrypt = automated, DigiCert = enterprise)
    """
    result = {
        "domain":         domain,
        "certificates":   [],
        "related_domains": set(),
        "earliest_cert":  None,
        "issuers":        set(),
        "error":          None,
    }

    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=20) as resp:
            certs = json.loads(resp.read().decode())

        for cert in certs[:100]:
            entry = {
                "id":          cert.get("id"),
                "not_before":  cert.get("not_before"),
                "not_after":   cert.get("not_after"),
                "issuer":      cert.get("issuer_name"),
                "common_name": cert.get("common_name"),
                "san":         cert.get("name_value", ""),
            }
            result["certificates"].append(entry)

            # Track earliest certificate
            if cert.get("not_before"):
                if not result["earliest_cert"] or cert["not_before"] < result["earliest_cert"]:
                    result["earliest_cert"] = cert["not_before"]

            # Track issuers
            issuer = cert.get("issuer_name", "")
            for ca in ["Let's Encrypt", "DigiCert", "Comodo", "Sectigo",
                       "GoDaddy", "GlobalSign", "Entrust", "Verisign"]:
                if ca.lower() in issuer.lower():
                    result["issuers"].add(ca)
                    break
            else:
                if issuer:
                    result["issuers"].add(issuer.split(",")[0].strip())

            # Extract SAN entries
            name_value = cert.get("name_value", "")
            for san in name_value.split("\n"):
                san = san.strip().lstrip("*.")
                if san and san != domain and "." in san:
                    if not any(x in san for x in ["ca.", "ocsp.", "crl.", "trust."]):
                        result["related_domains"].add(san)

    except (URLError, HTTPError) as e:
        result["error"] = f"Network error: {e}"
    except json.JSONDecodeError as e:
        result["error"] = f"Parse error: {e}"
    except Exception as e:
        result["error"] = str(e)

    result["related_domains"] = list(result["related_domains"])
    result["issuers"] = list(result["issuers"])
    return result


# ─────────────────────────────────────────────────────────────────────
# EMAIL AUTHENTICATION ANALYSIS
# ─────────────────────────────────────────────────────────────────────

def analyze_email_authentication(domain):
    """
    Analyze the complete email authentication posture of a domain.
    
    Why this matters forensically:
    
    Legitimate businesses set up SPF, DKIM, and DMARC because they need
    their email to work correctly and not get flagged as spam.
    
    Criminal infrastructure doesn't need email to work.
    They need domains to resolve. They need hosting.
    They don't set up email authentication.
    
    Missing or incomplete email authentication on a domain
    presenting itself as a business = red flag.
    """
    spf  = spf_record(domain)
    dmarc = dmarc_record(domain)
    dkim  = dkim_selectors(domain)
    mx    = mx_records(domain)

    # Score the authentication posture
    score = 0
    flags = []

    # SPF checks
    if spf.get("record"):
        score += 25
        if spf.get("policy") == "-all":
            score += 10  # Strict policy
        elif spf.get("policy") == "~all":
            score += 5   # Soft fail
    else:
        flags.append("NO_SPF: Domain has no SPF record")

    # DMARC checks
    if dmarc.get("record"):
        score += 25
        policy = dmarc.get("policy", "none")
        if policy == "reject":
            score += 15  # Strongest enforcement
        elif policy == "quarantine":
            score += 10
        elif policy == "none":
            flags.append("DMARC_NONE: DMARC policy is 'none' (not enforcing)")
    else:
        flags.append("NO_DMARC: Domain has no DMARC record")

    # DKIM checks
    if dkim.get("found"):
        score += 25
    else:
        flags.append("NO_DKIM: No common DKIM selectors found")

    # MX checks
    if mx.get("records"):
        score += 10
    else:
        flags.append("NO_MX: Domain has no mail servers")

    # Classify
    if score >= 80:
        posture = "PROFESSIONAL"
        interpretation = "Well-managed email infrastructure. Consistent with legitimate organization."
    elif score >= 50:
        posture = "PARTIAL"
        interpretation = "Incomplete email authentication. Mixed signals."
    elif score >= 25:
        posture = "MINIMAL"
        interpretation = "Minimal email authentication. Unusual for legitimate business."
    else:
        posture = "ABSENT"
        interpretation = "No email authentication. Strong indicator domain not used for legitimate email. Common in criminal infrastructure."

    return {
        "domain":         domain,
        "score":          score,
        "posture":        posture,
        "interpretation": interpretation,
        "flags":          flags,
        "spf":            spf,
        "dmarc":          dmarc,
        "dkim":           dkim,
        "mx":             mx,
        "provider":       mx.get("provider"),
        "dmarc_reports_to": dmarc.get("report_addresses", []),
    }


# ─────────────────────────────────────────────────────────────────────
# DOMAIN REPUTATION
# ─────────────────────────────────────────────────────────────────────

def spamhaus_check(domain):
    """
    Check domain against Spamhaus DBL (Domain Block List).
    Uses DNS-based lookup. No API key. Completely free.
    
    Returns classification if listed.
    """
    result = {
        "domain":   domain,
        "listed":   False,
        "category": None,
        "error":    None,
    }

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    dbl_categories = {
        "127.0.1.2": "spam domain",
        "127.0.1.4": "phishing domain",
        "127.0.1.5": "malware domain",
        "127.0.1.6": "botnet C&C domain",
        "127.0.1.102": "abused legit spam",
        "127.0.1.103": "abused spammed redirector",
        "127.0.1.104": "abused legit phishing",
        "127.0.1.105": "abused legit malware",
        "127.0.1.106": "abused legit botnet C&C",
    }

    try:
        lookup = f"{domain}.dbl.spamhaus.org"
        answers = dns.resolver.resolve(lookup, "A", lifetime=10)
        for rdata in answers:
            ip = str(rdata)
            if ip in dbl_categories:
                result["listed"] = True
                result["category"] = dbl_categories[ip]
                break

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["listed"] = False  # Not listed = good
    except dns.resolver.Timeout:
        result["error"] = "DNS timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def urlhaus_check(domain):
    """
    Check domain against URLhaus threat database.
    Direct API. Free. No account needed.
    """
    result = {
        "domain":  domain,
        "listed":  False,
        "urls":    [],
        "error":   None,
    }

    try:
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        data = f"host={domain}".encode()
        req = Request(url, data=data, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "CTF-Forensics/1.0"
        })
        with urlopen(req, timeout=10) as resp:
            response = json.loads(resp.read().decode())

        if response.get("query_status") == "is_host":
            result["listed"] = True
            urls = response.get("urls", [])[:5]
            result["urls"] = [u.get("url") for u in urls if u.get("url")]

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────

def _first(value):
    """Return first item if value is a list, else return value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_list(value):
    """Ensure value is a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_date(value):
    """Normalize date to ISO string."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]
    try:
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)
    except Exception:
        return str(value)


def _identify_mail_provider(mx_records):
    """Identify email provider from MX record hostnames."""
    if not mx_records:
        return None

    server_str = " ".join(r.get("server", "") for r in mx_records).lower()

    providers = {
        "google":         "Google Workspace",
        "googlemail":     "Google Workspace",
        "outlook":        "Microsoft 365",
        "hotmail":        "Microsoft 365",
        "protection.outlook": "Microsoft 365",
        "mailprotect":    "Proofpoint",
        "pphosted":       "Proofpoint",
        "mimecast":       "Mimecast",
        "barracuda":      "Barracuda",
        "messagelabs":    "Symantec",
        "amazonses":      "Amazon SES",
        "sendgrid":       "Sendgrid",
        "mailchimp":      "Mailchimp",
        "mailgun":        "Mailgun",
    }

    for keyword, provider in providers.items():
        if keyword in server_str:
            return provider

    return "Custom/Unknown"


# ─────────────────────────────────────────────────────────────────────
# MAIN MODULE CLASS
# ─────────────────────────────────────────────────────────────────────

class EmailDNSForensics:
    """
    Takes a domain name.
    Returns complete email and DNS identity picture.
    Logs everything to evidence journal.
    """

    def __init__(self, journal=None):
        self.journal = journal or EvidenceJournal()

    def analyze(self, domain):
        """
        Full email and DNS forensic analysis of a domain.
        
        Returns dict with all findings.
        """
        print(f"\n[CTF/M2] Email & DNS Forensics: {domain}")
        results = {
            "domain":    domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # WHOIS
        print(f"  [1/6] WHOIS lookup...")
        w = whois_lookup(domain)
        self.journal.log(
            module="m2_dns_email",
            query=f"WHOIS: {domain}",
            source="python-whois/direct-registry",
            response={k: v for k, v in w.items() if k != "raw"}
        )
        results["whois"] = w
        if w.get("registrant_name"):
            print(f"  └─ Registrant: {w['registrant_name']}")
        if w.get("registrant_email"):
            print(f"  └─ Email: {w['registrant_email']}")
        if w.get("created"):
            print(f"  └─ Registered: {w['created']}")
        if w.get("privacy_protected"):
            print(f"  └─ ⚠ Privacy protected registrant")

        # Email authentication
        print(f"  [2/6] Email authentication (SPF/DKIM/DMARC)...")
        auth = analyze_email_authentication(domain)
        self.journal.log(
            module="m2_dns_email",
            query=f"EMAIL_AUTH: {domain}",
            source="DNS/direct-TXT-queries",
            response={
                "posture": auth.get("posture"),
                "score":   auth.get("score"),
                "flags":   auth.get("flags"),
                "provider": auth.get("provider"),
                "dmarc_reports_to": auth.get("dmarc_reports_to"),
            }
        )
        results["email_auth"] = auth
        print(f"  └─ Email posture: {auth.get('posture')} (score: {auth.get('score')}/100)")
        if auth.get("flags"):
            for flag in auth["flags"]:
                print(f"  └─ ⚠ {flag}")
        if auth.get("provider"):
            print(f"  └─ Mail provider: {auth.get('provider')}")
        if auth.get("dmarc_reports_to"):
            print(f"  └─ DMARC reports to: {', '.join(auth['dmarc_reports_to'])}")

        # Certificate history
        print(f"  [3/6] Certificate history (crt.sh)...")
        certs = certificate_history(domain)
        self.journal.log(
            module="m2_dns_email",
            query=f"CERTS: {domain}",
            source="crt.sh/direct-API",
            response={
                "count":           len(certs.get("certificates", [])),
                "earliest":        certs.get("earliest_cert"),
                "issuers":         certs.get("issuers", []),
                "related_domains": certs.get("related_domains", [])[:10],
                "error":           certs.get("error"),
            }
        )
        results["certificates"] = certs
        cert_count = len(certs.get("certificates", []))
        print(f"  └─ Certificates found: {cert_count}")
        if certs.get("earliest_cert"):
            print(f"  └─ First certificate: {certs['earliest_cert']}")
        if certs.get("issuers"):
            print(f"  └─ Certificate issuers: {', '.join(certs['issuers'])}")
        if certs.get("related_domains"):
            print(f"  └─ Domains sharing certificates: {', '.join(certs['related_domains'][:3])}")

        # Spamhaus check
        print(f"  [4/6] Spamhaus DBL check...")
        spam = spamhaus_check(domain)
        self.journal.log(
            module="m2_dns_email",
            query=f"SPAMHAUS_DBL: {domain}",
            source="Spamhaus/DNS-based-lookup",
            response=spam
        )
        results["spamhaus"] = spam
        if spam.get("listed"):
            print(f"  └─ 🚩 LISTED IN SPAMHAUS DBL: {spam.get('category')}")
        else:
            print(f"  └─ Not listed in Spamhaus DBL")

        # URLhaus check
        print(f"  [5/6] URLhaus threat check...")
        urlhaus = urlhaus_check(domain)
        self.journal.log(
            module="m2_dns_email",
            query=f"URLHAUS: {domain}",
            source="URLhaus/direct-API",
            response=urlhaus
        )
        results["urlhaus"] = urlhaus
        if urlhaus.get("listed"):
            print(f"  └─ 🚩 LISTED IN URLHAUS: {len(urlhaus.get('urls', []))} malicious URLs")
        elif not urlhaus.get("error"):
            print(f"  └─ Not listed in URLhaus")

        # WHOIS history
        print(f"  [6/6] WHOIS history (archive.org)...")
        history = whois_history(domain)
        self.journal.log(
            module="m2_dns_email",
            query=f"WHOIS_HISTORY: {domain}",
            source="archive.org/CDX-API",
            response={
                "snapshot_count": len(history.get("snapshots", [])),
                "error": history.get("error"),
            }
        )
        results["whois_history"] = history
        snap_count = len(history.get("snapshots", []))
        print(f"  └─ Historical WHOIS snapshots: {snap_count}")

        # Build summary
        results["summary"] = self._summarize(results)

        return results

    def _summarize(self, results):
        """Plain-language summary of email/DNS findings."""
        w     = results.get("whois", {})
        auth  = results.get("email_auth", {})
        certs = results.get("certificates", {})
        spam  = results.get("spamhaus", {})
        uh    = results.get("urlhaus", {})

        red_flags = []
        green_flags = []

        if w.get("privacy_protected"):
            red_flags.append("Registrant identity hidden behind privacy service")
        if auth.get("posture") in ("ABSENT", "MINIMAL"):
            red_flags.append(f"Email authentication posture is {auth.get('posture')}")
        if spam.get("listed"):
            red_flags.append(f"Listed in Spamhaus DBL as: {spam.get('category')}")
        if uh.get("listed"):
            red_flags.append("Listed in URLhaus threat database")
        if not w.get("registrant_name") and not w.get("registrant_email"):
            red_flags.append("No registrant information available")
        if certs.get("earliest_cert"):
            red_flags.append(f"Domain first seen in certificate logs: {certs['earliest_cert'][:10]}")

        if not w.get("privacy_protected") and w.get("registrant_name"):
            green_flags.append(f"Registrant publicly identified: {w['registrant_name']}")
        if auth.get("posture") == "PROFESSIONAL":
            green_flags.append("Professional email authentication setup")
        if auth.get("dmarc_reports_to"):
            green_flags.append(f"DMARC reports sent to: {', '.join(auth['dmarc_reports_to'])}")

        return {
            "domain":          results.get("domain"),
            "registrant":      w.get("registrant_name"),
            "registrant_email": w.get("registrant_email"),
            "registered":      w.get("created"),
            "mail_provider":   auth.get("provider"),
            "email_posture":   auth.get("posture"),
            "threat_listed":   spam.get("listed") or uh.get("listed"),
            "red_flags":       red_flags,
            "green_flags":     green_flags,
            "related_domains": certs.get("related_domains", []),
        }


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 2 Email/DNS Forensics Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        forensics = EmailDNSForensics(journal=journal)

        # Test with a real domain
        print("\nTest 1: Analyze google.com (known good domain)")
        result = forensics.analyze("google.com")

        print(f"\nSummary:")
        s = result.get("summary", {})
        print(f"  Registrant:     {s.get('registrant', 'Unknown')}")
        print(f"  Email posture:  {s.get('email_posture', 'Unknown')}")
        print(f"  Mail provider:  {s.get('mail_provider', 'Unknown')}")
        print(f"  Threat listed:  {s.get('threat_listed', False)}")

        if s.get("red_flags"):
            print(f"\n  Red flags:")
            for f in s["red_flags"]:
                print(f"    🚩 {f}")

        if s.get("green_flags"):
            print(f"\n  Green flags:")
            for f in s["green_flags"]:
                print(f"    ✓ {f}")

        # Verify evidence chain
        print("\n" + "─" * 40)
        v = journal.verify()
        print(f"Evidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 2 self-test complete.")
        print("=" * 60)
