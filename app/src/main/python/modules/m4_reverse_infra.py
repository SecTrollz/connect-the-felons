#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 4 - Reverse Person-to-Infrastructure

One job: Given an identifier that already surfaced during an investigation
(a registrant email from Module 2's WHOIS lookup, a name from Module 3's
ownership chain), find what ADDITIONAL public infrastructure is tied to
that same identifier.

CORRECTION TO ORIGINAL BLUEPRINT:
The original architecture called for "reverse WHOIS by email/name/phone via
RDAP/WHOIS to all TLD registries." That capability doesn't exist as a free
direct protocol query. RDAP and WHOIS only support forward lookup — you
query a domain, you get its registrant. There is no live "give me every
domain registered to X" query against the registries themselves. That only
exists behind paid aggregators (DomainTools Reverse WHOIS, WhoisXML,
SecurityTrails) that maintain their own scraped historical index.

This module builds the equivalent capability from sources that genuinely
do support direct, free, structured reverse lookup:

  - GitHub commit search:     api.github.com (free, 60 req/hr unauthenticated,
                               5000/hr with a personal access token). Git
                               embeds the author's email in every commit by
                               default. Most people never scrub it. This is
                               usually more effective than WHOIS reverse
                               lookup ever was.

  - GitHub user lookup:       api.github.com. Once a username surfaces,
                               pulls public profile, org memberships, repos.

  - OpenCorporates officers:  api.opencorporates.com/v0.4/officers/search
                               Free tier, direct query. Indexes officers and
                               directors by name across 130+ jurisdictions.
                               This is the real reverse capability on the
                               corporate side — already used forward in M3
                               (company → owner), used backward here
                               (person → every company they're listed on).

  - Certificate transparency: crt.sh (free, direct query). EV/OV certs
                               embed the legal Organization field. Matching
                               on it finds other domains validated by the
                               same business entity.

  - Search dork generation:   Pure local, no network call. There's no free
                               API for "search the entire web" — Google and
                               Bing both charge for that. This generates the
                               manual queries an investigator runs themselves.

  - HIBP breach membership:   haveibeenpwned.com/api/v3. Requires a free API
                               key (HIBP killed keyless lookup in 2024).
                               Returns ONLY breach names and dates — never
                               passwords, never other leaked fields. Confirms
                               exposure, hands you nothing else.

SCOPE BOUNDARY:
This module deliberately does not integrate people-search/data-broker sites
(Spokeo, BeenVerified, Whitepages, TruePeopleSearch) or social media
scraping. Those aggregate home addresses and relatives scraped or leaked
from non-consensual sources, and querying them programmatically violates
their terms of service. That's a doxxing tool. This is an infrastructure
attribution tool. Everything here surfaces a record the entity itself
published — a commit, a corporate filing, a certificate.

Every query is logged to the evidence journal with a timestamp, same as
every other module. There's no technical way to stop someone from pointing
any OSINT tool at an unrelated private individual — that's true of Google
too — but the audit trail means every lookup is attributable and dated.
"""

import json
import os
import sys
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote_plus

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal


GITHUB_API = "https://api.github.com"


# ─────────────────────────────────────────────────────────────────────
# GITHUB - COMMIT SEARCH BY EMAIL
# ─────────────────────────────────────────────────────────────────────

def _github_headers(token=None):
    headers = {
        "User-Agent": "CTF-Forensics/1.0",
        "Accept": "application/vnd.github+json",
    }
    token = token or os.environ.get("CTF_GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_commits_by_email(email, token=None, limit=10):
    """
    Search GitHub for commits authored with this email address.

    Git embeds the author's email in every commit by default. This is
    one of the most reliable ways to tie an anonymous-looking email to
    a real GitHub identity — the commit history attached to it often
    spans years and reveals username, employer (via org repos), and
    writing style.
    """
    result = {
        "email": email,
        "commits": [],
        "usernames_found": set(),
        "repos_found": set(),
        "total_count": 0,
        "rate_limited": False,
        "error": None,
    }

    try:
        query = quote_plus(f"author-email:{email}")
        url = f"{GITHUB_API}/search/commits?q={query}&per_page={limit}"
        req = Request(url, headers=_github_headers(token))
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        result["total_count"] = data.get("total_count", 0)

        for item in data.get("items", [])[:limit]:
            commit = item.get("commit", {})
            author = commit.get("author", {})
            repo = item.get("repository", {})
            gh_author = item.get("author") or {}

            entry = {
                "sha":             item.get("sha"),
                "message":         (commit.get("message") or "")[:200],
                "author_name":     author.get("name"),
                "author_date":     author.get("date"),
                "repo":            repo.get("full_name"),
                "repo_url":        repo.get("html_url"),
                "github_username": gh_author.get("login"),
            }
            result["commits"].append(entry)

            if entry["github_username"]:
                result["usernames_found"].add(entry["github_username"])
            if entry["repo"]:
                result["repos_found"].add(entry["repo"])

    except HTTPError as e:
        if e.code == 403:
            result["rate_limited"] = True
            result["error"] = "GitHub rate limit hit. Set CTF_GITHUB_TOKEN env var for 5000/hr."
        elif e.code == 422:
            result["error"] = f"GitHub rejected query syntax: {e.reason}"
        else:
            result["error"] = f"HTTP {e.code}: {e.reason}"
    except (URLError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    result["usernames_found"] = list(result["usernames_found"])
    result["repos_found"] = list(result["repos_found"])
    return result


def github_user_profile(username, token=None):
    """
    Pull public profile data for a known GitHub username.
    Direct query, free, no auth required for public data.
    """
    result = {
        "username":      username,
        "name":          None,
        "company":       None,
        "email":         None,
        "location":      None,
        "bio":           None,
        "blog":          None,
        "public_repos":  None,
        "followers":     None,
        "created_at":    None,
        "organizations": [],
        "error":         None,
    }

    try:
        url = f"{GITHUB_API}/users/{username}"
        req = Request(url, headers=_github_headers(token))
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        result.update({
            "name":         data.get("name"),
            "company":      data.get("company"),
            "email":        data.get("email"),
            "location":     data.get("location"),
            "bio":          data.get("bio"),
            "blog":         data.get("blog"),
            "public_repos": data.get("public_repos"),
            "followers":    data.get("followers"),
            "created_at":   data.get("created_at"),
        })

        org_url = f"{GITHUB_API}/users/{username}/orgs"
        org_req = Request(org_url, headers=_github_headers(token))
        with urlopen(org_req, timeout=10) as resp:
            orgs = json.loads(resp.read().decode())
        result["organizations"] = [o.get("login") for o in orgs]

    except HTTPError as e:
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except (URLError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# OPENCORPORATES - OFFICER SEARCH (PERSON → COMPANIES)
# ─────────────────────────────────────────────────────────────────────

def opencorporates_officer_search(name, jurisdiction=None):
    """
    Given a person's name, find every company where they appear as an
    officer or director. OpenCorporates indexes officers, not just
    companies — this is its real reverse-lookup endpoint.
    """
    result = {
        "name":      name,
        "officers":  [],
        "companies": set(),
        "error":     None,
    }

    try:
        query = quote_plus(name)
        url = f"https://api.opencorporates.com/v0.4/officers/search?q={query}"
        if jurisdiction:
            url += f"&jurisdiction_code={jurisdiction}"

        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        officers = data.get("results", {}).get("officers", [])
        for o in officers[:20]:
            officer = o.get("officer", {})
            company = officer.get("company", {})

            entry = {
                "name":           officer.get("name"),
                "position":       officer.get("position"),
                "start_date":     officer.get("start_date"),
                "end_date":       officer.get("end_date"),
                "company_name":   company.get("name"),
                "company_number": company.get("company_number"),
                "jurisdiction":   company.get("jurisdiction_code"),
            }
            result["officers"].append(entry)
            if entry["company_name"]:
                result["companies"].add(entry["company_name"])

    except HTTPError as e:
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except (URLError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    result["companies"] = list(result["companies"])
    return result


# ─────────────────────────────────────────────────────────────────────
# CERTIFICATE TRANSPARENCY - ORGANIZATION SEARCH
# ─────────────────────────────────────────────────────────────────────

def certificate_org_search(org_name):
    """
    Search certificate transparency logs for an organization name.

    EV/OV certificates embed the legal Organization (O=) field of
    whoever validated ownership. DV certs (the vast majority, including
    every Let's Encrypt cert) don't include this field, so this only
    hits for organization-validated certs — but when it hits, it's a
    direct, citable link between a named legal entity and infrastructure.
    """
    result = {
        "org_name":     org_name,
        "domains":      set(),
        "certificates": [],
        "error":        None,
    }

    try:
        query = quote_plus(org_name)
        url = f"https://crt.sh/?q={query}&output=json"
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=20) as resp:
            certs = json.loads(resp.read().decode())

        for cert in certs[:50]:
            entry = {
                "common_name": cert.get("common_name"),
                "issuer":      cert.get("issuer_name"),
                "not_before":  cert.get("not_before"),
            }
            result["certificates"].append(entry)
            if entry["common_name"]:
                result["domains"].add(entry["common_name"].lstrip("*."))

    except HTTPError as e:
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except (URLError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    result["domains"] = list(result["domains"])
    return result


# ─────────────────────────────────────────────────────────────────────
# HAVE I BEEN PWNED - BREACH MEMBERSHIP (METADATA ONLY)
# ─────────────────────────────────────────────────────────────────────

def hibp_breach_check(email, api_key=None):
    """
    Check if an email appears in known data breaches.

    Returns ONLY breach names and dates. Never returns passwords, never
    returns other leaked fields. Confirms exposure, hands you nothing else.

    Requires a free key from haveibeenpwned.com/API/Key — HIBP stopped
    allowing fully keyless lookups in 2024.
    """
    result = {
        "email":    email,
        "breaches": [],
        "checked":  False,
        "error":    None,
    }

    api_key = api_key or os.environ.get("CTF_HIBP_KEY")
    if not api_key:
        result["error"] = "HIBP requires a free API key. Get one at haveibeenpwned.com/API/Key and set CTF_HIBP_KEY."
        return result

    try:
        encoded = quote_plus(email)
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}"
        req = Request(url, headers={
            "User-Agent": "CTF-Forensics/1.0",
            "hibp-api-key": api_key,
        })
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        for breach in data:
            result["breaches"].append({
                "name":         breach.get("Name"),
                "date":         breach.get("BreachDate"),
                "data_classes": breach.get("DataClasses", []),
            })
        result["checked"] = True

    except HTTPError as e:
        if e.code == 404:
            result["checked"] = True  # No breaches found - this is a success, not an error
        else:
            result["error"] = f"HTTP {e.code}: {e.reason}"
    except (URLError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# SEARCH DORK GENERATOR (NO NETWORK CALL)
# ─────────────────────────────────────────────────────────────────────

def generate_search_dorks(identifier, identifier_type="auto"):
    """
    Generate manual search engine queries for an identifier.

    There's no free API for "search the entire web" - Google and Bing
    both charge for programmatic access. This generates the queries an
    investigator runs by hand, including site-restricted searches that
    reach things no automated tool can (forum posts, cached pages,
    PDF filings).
    """
    if identifier_type == "auto":
        identifier_type = "email" if "@" in identifier else "name"

    if identifier_type == "email":
        dorks = [
            f'"{identifier}"',
            f'"{identifier}" site:pastebin.com',
            f'"{identifier}" site:github.com',
            f'"{identifier}" filetype:pdf',
            f'"{identifier}" site:linkedin.com',
        ]
    else:
        dorks = [
            f'"{identifier}"',
            f'"{identifier}" site:sec.gov',
            f'"{identifier}" site:opencorporates.com',
            f'"{identifier}" filetype:pdf "officer" OR "director"',
            f'"{identifier}" site:courtlistener.com',
        ]

    return {
        "identifier": identifier,
        "type":       identifier_type,
        "dorks":      dorks,
        "note":       "Run these manually in a search engine. No automated API exists for this without a paid search license.",
    }


# ─────────────────────────────────────────────────────────────────────
# MAIN MODULE CLASS
# ─────────────────────────────────────────────────────────────────────

class ReverseInfrastructureMapper:
    """
    Takes an identifier already surfaced during an investigation - an
    email, a name - and maps out what additional public infrastructure
    is tied to it.

    Intended use: extending attribution on an entity already under
    investigation. The registrant email Module 2 pulled off a domain's
    WHOIS record. A name Module 3 surfaced while tracing an ownership
    chain. Every lookup here is logged to the evidence journal with a
    timestamp, same as every other module.
    """

    def __init__(self, journal=None, github_token=None, hibp_key=None):
        self.journal      = journal or EvidenceJournal()
        self.github_token = github_token
        self.hibp_key     = hibp_key

    def map_email(self, email):
        """Full reverse mapping starting from an email address."""
        print(f"\n[CTF/M4] Reverse infrastructure mapping: {email}")
        result = {"email": email, "timestamp": datetime.now(timezone.utc).isoformat()}

        # GitHub commits
        print(f"  [1/4] GitHub commit search...")
        commits = github_commits_by_email(email, token=self.github_token)
        self.journal.log(
            module="m4_reverse_infra",
            query=f"GITHUB_COMMITS: {email}",
            source="api.github.com/search/commits",
            response={
                "total_count":     commits.get("total_count"),
                "usernames_found": commits.get("usernames_found"),
                "repos_found":     commits.get("repos_found", [])[:10],
                "error":           commits.get("error"),
            }
        )
        result["github_commits"] = commits
        if commits.get("total_count"):
            print(f"  └─ {commits['total_count']} commits found")
        if commits.get("usernames_found"):
            print(f"  └─ GitHub usernames: {', '.join(commits['usernames_found'])}")
        if commits.get("repos_found"):
            print(f"  └─ Repos: {', '.join(commits['repos_found'][:3])}")
        if commits.get("error"):
            print(f"  └─ {commits['error']}")

        # GitHub profiles for any usernames found
        result["github_profiles"] = {}
        for username in commits.get("usernames_found", [])[:3]:
            profile = github_user_profile(username, token=self.github_token)
            self.journal.log(
                module="m4_reverse_infra",
                query=f"GITHUB_PROFILE: {username}",
                source="api.github.com/users",
                response=profile
            )
            result["github_profiles"][username] = profile
            if profile.get("name") or profile.get("company"):
                print(f"  └─ @{username}: {profile.get('name')} — {profile.get('company')}")

        # HIBP breach check
        print(f"  [2/4] Breach membership check (HIBP)...")
        breaches = hibp_breach_check(email, api_key=self.hibp_key)
        self.journal.log(
            module="m4_reverse_infra",
            query=f"HIBP: {email}",
            source="haveibeenpwned.com/api/v3",
            response={
                "checked":      breaches.get("checked"),
                "breach_count": len(breaches.get("breaches", [])),
                "breach_names": [b["name"] for b in breaches.get("breaches", [])],
                "error":        breaches.get("error"),
            }
        )
        result["breaches"] = breaches
        if breaches.get("breaches"):
            names = [b["name"] for b in breaches["breaches"]]
            print(f"  └─ 🚩 Found in {len(names)} breach(es): {', '.join(names[:5])}")
        elif breaches.get("checked"):
            print(f"  └─ No known breaches")
        elif breaches.get("error"):
            print(f"  └─ {breaches['error']}")

        # Certificate org search using the domain part as a guess
        domain_part = email.split("@")[-1]
        print(f"  [3/4] Certificate transparency cross-check...")
        certs = certificate_org_search(domain_part)
        self.journal.log(
            module="m4_reverse_infra",
            query=f"CERT_ORG: {domain_part}",
            source="crt.sh/direct-API",
            response={"domains_found": certs.get("domains", []), "error": certs.get("error")}
        )
        result["certificate_domains"] = certs
        if certs.get("domains"):
            print(f"  └─ Domains: {', '.join(certs['domains'][:5])}")
        if certs.get("error"):
            print(f"  └─ {certs['error']}")

        # Search dorks
        print(f"  [4/4] Generating manual search queries...")
        dorks = generate_search_dorks(email, "email")
        self.journal.log(
            module="m4_reverse_infra",
            query=f"DORKS_GENERATED: {email}",
            source="local-generator",
            response={"dork_count": len(dorks["dorks"])}
        )
        result["search_dorks"] = dorks
        print(f"  └─ {len(dorks['dorks'])} manual search queries generated")

        return result

    def map_name(self, name, jurisdiction=None):
        """Full reverse mapping starting from a person's name."""
        print(f"\n[CTF/M4] Reverse infrastructure mapping: {name}")
        result = {"name": name, "timestamp": datetime.now(timezone.utc).isoformat()}

        # OpenCorporates officer search
        print(f"  [1/2] OpenCorporates officer search...")
        officers = opencorporates_officer_search(name, jurisdiction)
        self.journal.log(
            module="m4_reverse_infra",
            query=f"OFFICER_SEARCH: {name}",
            source="api.opencorporates.com/officers",
            response={
                "companies_found": officers.get("companies", []),
                "officer_count":   len(officers.get("officers", [])),
                "error":           officers.get("error"),
            }
        )
        result["companies"] = officers
        if officers.get("companies"):
            print(f"  └─ Companies: {', '.join(officers['companies'][:5])}")
        if officers.get("error"):
            print(f"  └─ {officers['error']}")

        # Search dorks
        print(f"  [2/2] Generating manual search queries...")
        dorks = generate_search_dorks(name, "name")
        self.journal.log(
            module="m4_reverse_infra",
            query=f"DORKS_GENERATED: {name}",
            source="local-generator",
            response={"dork_count": len(dorks["dorks"])}
        )
        result["search_dorks"] = dorks
        print(f"  └─ {len(dorks['dorks'])} manual search queries generated")

        return result

    def map(self, identifier):
        """Auto-detect identifier type and run the appropriate mapping."""
        if "@" in identifier:
            return self.map_email(identifier)
        return self.map_name(identifier)


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 4 Reverse Infrastructure Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        mapper = ReverseInfrastructureMapper(journal=journal)

        # Test with a well-known public OSS maintainer's commit email -
        # the canonical public test fixture for git/GitHub tooling demos,
        # attached to millions of public Linux kernel commits. Not a
        # private individual's personal address.
        print("\nTest 1: GitHub commit search (public OSS maintainer email)")
        result = mapper.map_email("torvalds@linux-foundation.org")

        commits = result.get("github_commits", {})
        print(f"\n  Total commits found: {commits.get('total_count', 0)}")
        print(f"  Usernames found: {commits.get('usernames_found', [])}")

        # Test dork generation - always works, no network
        print("\nTest 2: Search dork generation (local, no network)")
        dorks = generate_search_dorks("test@example.com", "email")
        for d in dorks["dorks"][:3]:
            print(f"  → {d}")

        # Test OpenCorporates - likely blocked in this sandbox, expected
        print("\nTest 3: OpenCorporates officer search")
        name_result = mapper.map_name("Tim Cook")
        if name_result.get("companies", {}).get("error"):
            print(f"  (Expected in sandboxed env: {name_result['companies']['error']})")

        # Verify evidence chain
        print("\n" + "─" * 40)
        v = journal.verify()
        print(f"Evidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 4 self-test complete.")
        print("=" * 60)
