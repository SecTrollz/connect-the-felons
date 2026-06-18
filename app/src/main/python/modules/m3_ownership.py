#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 3 - Ownership Chain Traversal

One job: Given a company name, domain, or person, recursively trace
corporate ownership until you hit a natural person, public company,
government entity, or detect a loop.

Data sources (all direct queries, no paid APIs):
  - SEC EDGAR:      data.sec.gov/api (US public companies, free)
  - OpenCorporates: api.opencorporates.com (global registries, free tier)
  - FinCEN BOI:     boiefiling.fincen.gov (Beneficial Ownership, CTA 2024)
  - OFAC SDN:       Local download from treasury.gov/ofac (sanctions list)
  - ICIJ Offshore:  offshoreleaks.icij.org/api (Panama/Pandora papers, free)

Terminal conditions (stop recursing when you hit):
  - Natural person (a human being with a name)
  - Public company (SEC-registered, clean chain)
  - Government entity
  - Dissolved company (chain ends)
  - Loop detected (A → B → C → A = fraud signal)
"""

import json
import re
import sys
import os
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote_plus

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal


# ─────────────────────────────────────────────────────────────────────
# ENTITY TYPES
# ─────────────────────────────────────────────────────────────────────

class EntityType:
    NATURAL_PERSON  = "NATURAL_PERSON"    # Human being
    PUBLIC_COMPANY  = "PUBLIC_COMPANY"    # SEC-registered
    PRIVATE_COMPANY = "PRIVATE_COMPANY"   # State-registered LLC/Corp
    GOVERNMENT      = "GOVERNMENT"        # Government entity
    DISSOLVED       = "DISSOLVED"         # Company no longer active
    UNKNOWN         = "UNKNOWN"           # Cannot determine


class TraversalResult:
    TERMINAL_PERSON    = "TERMINAL_PERSON"     # Hit a real person
    TERMINAL_PUBLIC    = "TERMINAL_PUBLIC"     # Hit a public company
    TERMINAL_GOVT      = "TERMINAL_GOVT"       # Hit a government entity
    TERMINAL_DISSOLVED = "TERMINAL_DISSOLVED"  # Company is dissolved
    LOOP_DETECTED      = "LOOP_DETECTED"       # Circular ownership
    MAX_DEPTH          = "MAX_DEPTH"           # Hit recursion limit
    INSUFFICIENT_DATA  = "INSUFFICIENT_DATA"   # Can't go deeper


# ─────────────────────────────────────────────────────────────────────
# SEC EDGAR
# ─────────────────────────────────────────────────────────────────────

def edgar_company_search(name):
    """
    Search SEC EDGAR for company by name.
    Returns list of matching companies with CIK numbers.
    
    SEC EDGAR API is free, no key, direct query.
    """
    result = {
        "query":    name,
        "results":  [],
        "error":    None,
    }

    try:
        encoded = quote_plus(name)
        url = f"https://efts.sec.gov/LATEST/search-index?q={encoded}&dateRange=custom&startdt=1990-01-01&forms=10-K,10-K405,10-KSB"
        req = Request(url, headers={
            "User-Agent": "CTF-Forensics/1.0 forensics@example.com",
            "Accept": "application/json",
        })
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        hits = data.get("hits", {}).get("hits", [])
        for hit in hits[:10]:
            src = hit.get("_source", {})
            result["results"].append({
                "name":        src.get("entity_name"),
                "cik":         src.get("file_num"),
                "form_type":   src.get("form_type"),
                "filed":       src.get("period_of_report"),
            })

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


def edgar_company_facts(cik):
    """
    Fetch company facts from SEC EDGAR by CIK number.
    Returns registrant name, addresses, officers, SIC code.
    """
    result = {
        "cik":          cik,
        "name":         None,
        "entity_type":  None,
        "sic":          None,
        "sic_desc":     None,
        "addresses":    [],
        "phone":        None,
        "state":        None,
        "fiscal_year":  None,
        "error":        None,
    }

    try:
        # Pad CIK to 10 digits
        cik_padded = str(cik).lstrip("0").zfill(10)
        url = f"https://data.sec.gov/submissions/CIK{cik_padded}.json"
        req = Request(url, headers={
            "User-Agent": "CTF-Forensics/1.0 forensics@example.com",
            "Accept": "application/json",
        })
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        result["name"]        = data.get("name")
        result["entity_type"] = data.get("entityType")
        result["sic"]         = data.get("sic")
        result["sic_desc"]    = data.get("sicDescription")
        result["phone"]       = data.get("phone")
        result["state"]       = data.get("stateOfIncorporation")
        result["fiscal_year"] = data.get("fiscalYearEnd")

        # Addresses
        for addr_type in ("mailing", "business"):
            addr = data.get("addresses", {}).get(addr_type, {})
            if addr:
                result["addresses"].append({
                    "type":    addr_type,
                    "street1": addr.get("street1"),
                    "street2": addr.get("street2"),
                    "city":    addr.get("city"),
                    "state":   addr.get("stateOrCountry"),
                    "zip":     addr.get("zipCode"),
                })

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# OPENCORPORATES
# ─────────────────────────────────────────────────────────────────────

def opencorporates_search(name, jurisdiction=None):
    """
    Search OpenCorporates for company by name.
    Free tier: 50 searches/day. No key required for basic search.
    
    OpenCorporates aggregates company registries from 130+ jurisdictions.
    """
    result = {
        "query":       name,
        "jurisdiction": jurisdiction,
        "results":     [],
        "error":       None,
    }

    try:
        encoded = quote_plus(name)
        url = f"https://api.opencorporates.com/v0.4/companies/search?q={encoded}"
        if jurisdiction:
            url += f"&jurisdiction_code={jurisdiction}"

        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        companies = (
            data.get("results", {}).get("companies", [])
        )

        for c in companies[:10]:
            co = c.get("company", {})
            result["results"].append({
                "name":           co.get("name"),
                "company_number": co.get("company_number"),
                "jurisdiction":   co.get("jurisdiction_code"),
                "status":         co.get("current_status"),
                "company_type":   co.get("company_type"),
                "incorporated":   co.get("incorporation_date"),
                "registered_address": co.get("registered_address", {}).get("in_full"),
                "opencorporates_url": co.get("opencorporates_url"),
            })

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


def opencorporates_officers(company_number, jurisdiction):
    """
    Get officers (directors, beneficial owners) for a company.
    Returns names and roles of people associated with the company.
    """
    result = {
        "company_number": company_number,
        "jurisdiction":   jurisdiction,
        "officers":       [],
        "error":          None,
    }

    try:
        url = f"https://api.opencorporates.com/v0.4/companies/{jurisdiction}/{company_number}"
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        co = data.get("results", {}).get("company", {})
        for officer in co.get("officers", []):
            o = officer.get("officer", {})
            result["officers"].append({
                "name":       o.get("name"),
                "role":       o.get("role"),
                "start_date": o.get("start_date"),
                "end_date":   o.get("end_date"),
                "current":    o.get("current_status") == "Active",
            })

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# OFAC SANCTIONS
# ─────────────────────────────────────────────────────────────────────

def ofac_check(name, data_dir=None):
    """
    Check name against OFAC Specially Designated Nationals (SDN) list.
    
    The SDN list is downloaded locally from treasury.gov/ofac.
    No external query at check time. Updates weekly.
    
    To download:
      wget https://www.treasury.gov/ofac/downloads/sdn_mini.xml
      Place in ctf/data/ofac/sdn_mini.xml
    
    Returns match results with confidence score.
    """
    result = {
        "name":        name,
        "matches":     [],
        "checked":     False,
        "error":       None,
    }

    if data_dir is None:
        data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ofac"
        )

    sdn_file = os.path.join(data_dir, "sdn_mini.xml")
    if not os.path.exists(sdn_file):
        result["error"] = f"OFAC database not found at {sdn_file}. Download from treasury.gov/ofac"
        return result

    try:
        # Simple name matching - normalize both strings
        name_clean = re.sub(r"[^a-zA-Z0-9\s]", "", name).lower()
        name_parts = set(name_clean.split())

        with open(sdn_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Parse SDN entries by regex (avoids XML library dependency)
        entries = re.findall(
            r"<sdnEntry>(.*?)</sdnEntry>",
            content, re.DOTALL
        )

        for entry in entries:
            # Extract first name and last name
            first = re.search(r"<firstName>(.*?)</firstName>", entry)
            last  = re.search(r"<lastName>(.*?)</lastName>", entry)
            uid   = re.search(r"<uid>(.*?)</uid>", entry)
            sdn_type = re.search(r"<sdnType>(.*?)</sdnType>", entry)

            if not last:
                continue

            entry_name = " ".join(filter(None, [
                first.group(1) if first else "",
                last.group(1) if last else "",
            ])).strip()

            entry_clean = re.sub(r"[^a-zA-Z0-9\s]", "", entry_name).lower()
            entry_parts = set(entry_clean.split())

            # Calculate match score
            if name_parts and entry_parts:
                overlap = len(name_parts & entry_parts)
                score = overlap / max(len(name_parts), len(entry_parts))

                if score >= 0.8:  # 80% word overlap = match
                    result["matches"].append({
                        "name":       entry_name,
                        "uid":        uid.group(1) if uid else None,
                        "type":       sdn_type.group(1) if sdn_type else None,
                        "confidence": round(score * 100),
                    })

        result["checked"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# ICIJ OFFSHORE LEAKS
# ─────────────────────────────────────────────────────────────────────

def icij_search(name):
    """
    Search ICIJ Offshore Leaks database.
    Contains entities from Panama Papers, Paradise Papers, Pandora Papers.
    Free API. No account. Direct query.
    """
    result = {
        "name":    name,
        "results": [],
        "error":   None,
    }

    try:
        encoded = quote_plus(name)
        url = f"https://offshoreleaks.icij.org/api/v1/search?q={encoded}&limit=10"
        req = Request(url, headers={"User-Agent": "CTF-Forensics/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        for node in data.get("nodes", []):
            result["results"].append({
                "name":        node.get("name"),
                "type":        node.get("type"),
                "jurisdiction": node.get("jurisdiction"),
                "country":     node.get("country"),
                "status":      node.get("status"),
                "source_id":   node.get("sourceId"),
                "dataset":     node.get("dataset"),  # e.g. "Panama Papers"
            })

    except (URLError, HTTPError, json.JSONDecodeError) as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────
# OWNERSHIP GRAPH NODE
# ─────────────────────────────────────────────────────────────────────

class OwnershipNode:
    """Represents one entity in the ownership chain."""

    def __init__(self, name, entity_type=EntityType.UNKNOWN,
                 source=None, metadata=None):
        self.name        = name
        self.entity_type = entity_type
        self.source      = source
        self.metadata    = metadata or {}
        self.owners      = []   # Entities that own this one
        self.depth       = 0

    def to_dict(self):
        return {
            "name":        self.name,
            "entity_type": self.entity_type,
            "source":      self.source,
            "depth":       self.depth,
            "metadata":    self.metadata,
            "owners":      [o.to_dict() for o in self.owners],
        }


# ─────────────────────────────────────────────────────────────────────
# MAIN MODULE CLASS
# ─────────────────────────────────────────────────────────────────────

class OwnershipTraverser:
    """
    Recursively trace corporate ownership from company → owners → owners
    until hitting a terminal condition.
    
    Max depth: 10 (prevents infinite loops even if loop detection fails)
    """

    MAX_DEPTH = 10

    def __init__(self, journal=None):
        self.journal   = journal or EvidenceJournal()
        self.visited   = set()   # Tracks seen entities for loop detection
        self.ofac_dir  = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ofac"
        )

    def trace(self, entity_name, jurisdiction=None):
        """
        Entry point. Trace ownership chain from a company name.
        
        Args:
            entity_name:  Company or person name to trace
            jurisdiction: Optional country/state code (e.g. "us_de", "gb")
            
        Returns:
            dict: Complete ownership chain with all findings
        """
        print(f"\n[CTF/M3] Ownership chain: {entity_name}")
        self.visited = set()

        root = OwnershipNode(name=entity_name)
        self._traverse(root, jurisdiction=jurisdiction)

        result = {
            "query":      entity_name,
            "chain":      root.to_dict(),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "depth_reached": self._max_depth(root),
            "natural_persons": self._collect_persons(root),
            "ofac_flags":   self._collect_ofac(root),
            "offshore_flags": self._collect_offshore(root),
        }

        self.journal.log(
            module="m3_ownership",
            query=f"OWNERSHIP_CHAIN: {entity_name}",
            source="SEC-EDGAR+OpenCorporates+ICIJ",
            response={
                "depth": result["depth_reached"],
                "natural_persons": result["natural_persons"],
                "ofac_flags": len(result["ofac_flags"]),
                "offshore_flags": len(result["offshore_flags"]),
            }
        )

        return result

    def _traverse(self, node, depth=0, jurisdiction=None):
        """Recursive traversal. Returns terminal reason."""
        node.depth = depth

        # Terminal: too deep
        if depth >= self.MAX_DEPTH:
            node.entity_type = EntityType.UNKNOWN
            print(f"  {'  ' * depth}[MAX_DEPTH] {node.name}")
            return TraversalResult.MAX_DEPTH

        # Terminal: loop detected
        key = node.name.lower().strip()
        if key in self.visited:
            print(f"  {'  ' * depth}[LOOP] {node.name}")
            node.metadata["loop_detected"] = True
            return TraversalResult.LOOP_DETECTED
        self.visited.add(key)

        print(f"  {'  ' * depth}→ {node.name}")

        # Check OFAC sanctions
        ofac = ofac_check(node.name, self.ofac_dir)
        if ofac.get("checked") and ofac.get("matches"):
            node.metadata["ofac_matches"] = ofac["matches"]
            print(f"  {'  ' * depth}  🚩 OFAC MATCH: {ofac['matches'][0]['type']}")

        # Check ICIJ offshore leaks
        icij = icij_search(node.name)
        self.journal.log(
            module="m3_ownership",
            query=f"ICIJ: {node.name}",
            source="ICIJ-OffshoreLEaks-API",
            response=icij
        )
        if icij.get("results"):
            node.metadata["icij_matches"] = icij["results"]
            datasets = list(set(r.get("dataset") for r in icij["results"] if r.get("dataset")))
            print(f"  {'  ' * depth}  🚩 ICIJ OFFSHORE: {', '.join(datasets)}")

        # Try SEC EDGAR (US public companies)
        edgar = edgar_company_search(node.name)
        self.journal.log(
            module="m3_ownership",
            query=f"EDGAR: {node.name}",
            source="SEC-EDGAR-API",
            response=edgar
        )

        if edgar.get("results"):
            node.entity_type = EntityType.PUBLIC_COMPANY
            node.source      = "SEC EDGAR"
            node.metadata["edgar"] = edgar["results"][0]
            print(f"  {'  ' * depth}  ✓ Public company (SEC registered)")
            return TraversalResult.TERMINAL_PUBLIC

        # Try OpenCorporates (global private companies)
        oc = opencorporates_search(node.name, jurisdiction)
        self.journal.log(
            module="m3_ownership",
            query=f"OPENCORPORATES: {node.name}",
            source="OpenCorporates-API",
            response=oc
        )

        if oc.get("results"):
            co = oc["results"][0]
            node.source   = "OpenCorporates"
            node.metadata["opencorporates"] = co

            status = co.get("status", "").lower()
            if "dissolved" in status or "inactive" in status:
                node.entity_type = EntityType.DISSOLVED
                print(f"  {'  ' * depth}  ✓ Dissolved company")
                return TraversalResult.TERMINAL_DISSOLVED

            node.entity_type = EntityType.PRIVATE_COMPANY

            # Get officers to find owners
            if co.get("company_number") and co.get("jurisdiction"):
                officers = opencorporates_officers(
                    co["company_number"], co["jurisdiction"]
                )
                self.journal.log(
                    module="m3_ownership",
                    query=f"OFFICERS: {co['company_number']}/{co['jurisdiction']}",
                    source="OpenCorporates-API",
                    response=officers
                )

                for officer in officers.get("officers", []):
                    if not officer.get("current"):
                        continue

                    owner = OwnershipNode(
                        name=officer.get("name", "Unknown"),
                        metadata={"role": officer.get("role")}
                    )

                    # Classify: is this a person or another company?
                    name = officer.get("name", "")
                    if _looks_like_person(name):
                        owner.entity_type = EntityType.NATURAL_PERSON
                        print(f"  {'  ' * depth}  ✓ Natural person: {name} ({officer.get('role')})")
                        node.owners.append(owner)
                    else:
                        # Another company - recurse
                        node.owners.append(owner)
                        self._traverse(owner, depth + 1, jurisdiction)

        else:
            # Could not find in any registry
            if _looks_like_person(node.name):
                node.entity_type = EntityType.NATURAL_PERSON
                print(f"  {'  ' * depth}  ✓ Natural person: {node.name}")
                return TraversalResult.TERMINAL_PERSON

        return TraversalResult.INSUFFICIENT_DATA

    def _max_depth(self, node):
        """Find the maximum depth reached in the traversal."""
        if not node.owners:
            return node.depth
        return max(self._max_depth(o) for o in node.owners)

    def _collect_persons(self, node):
        """Collect all natural persons found in the chain."""
        persons = []
        if node.entity_type == EntityType.NATURAL_PERSON:
            persons.append({
                "name":   node.name,
                "depth":  node.depth,
                "source": node.source,
                "role":   node.metadata.get("role"),
            })
        for owner in node.owners:
            persons.extend(self._collect_persons(owner))
        return persons

    def _collect_ofac(self, node):
        """Collect all OFAC matches in the chain."""
        flags = []
        if node.metadata.get("ofac_matches"):
            for match in node.metadata["ofac_matches"]:
                flags.append({
                    "entity": node.name,
                    "depth":  node.depth,
                    "match":  match,
                })
        for owner in node.owners:
            flags.extend(self._collect_ofac(owner))
        return flags

    def _collect_offshore(self, node):
        """Collect all ICIJ offshore leaks matches."""
        flags = []
        if node.metadata.get("icij_matches"):
            for match in node.metadata["icij_matches"]:
                flags.append({
                    "entity":  node.name,
                    "depth":   node.depth,
                    "dataset": match.get("dataset"),
                    "type":    match.get("type"),
                })
        for owner in node.owners:
            flags.extend(self._collect_offshore(owner))
        return flags


# ─────────────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────────────

def _looks_like_person(name):
    """
    Heuristic: does this name look like a human being or a company?
    
    Company indicators: LLC, Inc, Corp, Ltd, GmbH, Holdings, Group, etc.
    Person indicators: First + Last name pattern, no corporate suffixes.
    """
    company_suffixes = [
        "llc", "inc", "corp", "ltd", "limited", "holdings", "group",
        "trust", "foundation", "gmbh", "sa", "bv", "srl", "plc",
        "company", "co.", "partners", "associates", "enterprises",
        "ventures", "capital", "management", "services", "solutions",
        "technologies", "international", "global",
    ]
    name_lower = name.lower()
    for suffix in company_suffixes:
        if suffix in name_lower:
            return False

    # Looks like "First Last" or "Last, First"
    parts = name.strip().split()
    if 1 < len(parts) <= 4:
        return True

    return False


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 3 Ownership Chain Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        traverser = OwnershipTraverser(journal=journal)

        # Test with Apple Inc (known public company - should terminate quickly)
        print("\nTest: Trace 'Apple Inc'")
        result = traverser.trace("Apple Inc")

        print(f"\nResults:")
        print(f"  Max depth: {result['depth_reached']}")
        print(f"  Natural persons found: {len(result['natural_persons'])}")
        for p in result['natural_persons'][:3]:
            print(f"    → {p['name']} ({p.get('role', 'Unknown role')})")
        print(f"  OFAC flags: {len(result['ofac_flags'])}")
        print(f"  Offshore flags: {len(result['offshore_flags'])}")

        # Verify evidence chain
        print("\n" + "─" * 40)
        v = journal.verify()
        print(f"Evidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 3 self-test complete.")
        print("=" * 60)
