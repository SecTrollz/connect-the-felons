#!/usr/bin/env python3
"""
CONNECT THE FELONS
Evidence Journal - SHA-256 Chain of Custody

One job: Cryptographically lock every piece of evidence the moment
it is discovered so it cannot be altered after the fact.

Every module imports this. Every finding gets logged here immediately
upon discovery before any processing begins.

Chain structure:
  entry_hash = SHA-256(sequence + timestamp + module + query + source + response + previous_hash)

If any entry is altered after writing, every subsequent hash in the
chain becomes invalid. The chain proves integrity.

Admissibility basis: Federal Rules of Evidence 901(b)(9)
"""

import hashlib
import json
import uuid
import os
from datetime import datetime, timezone
from pathlib import Path


class EvidenceJournal:
    """
    SHA-256 locked evidence chain for forensic investigations.
    
    Usage:
        journal = EvidenceJournal()
        journal.log(
            module="m1_infrastructure",
            query="dig +short A ssiloc.com",
            source="DNS/system",
            response="192.0.2.88"
        )
    """

    def __init__(self, investigation_id=None, base_dir=None):
        """
        Initialize a new investigation or resume an existing one.
        
        Args:
            investigation_id: UUID string. If None, generates new investigation.
            base_dir: Path to store evidence chains. Defaults to ./investigations/evidence_chains/
        """
        self.investigation_id = investigation_id or str(uuid.uuid4())
        self.base_dir = Path(base_dir or "investigations/evidence_chains")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        self.chain_file = self.base_dir / f"{self.investigation_id}.jsonl"
        self.sequence = 0
        self.previous_hash = "GENESIS"
        
        # Resume existing investigation if chain file exists
        if self.chain_file.exists():
            self._resume()
        else:
            self._initialize()

    # ─────────────────────────────────────────────────────────────
    # PUBLIC INTERFACE
    # ─────────────────────────────────────────────────────────────

    def log(self, module, query, source, response, investigator="evan"):
        """
        Log a finding to the evidence chain.
        
        Every piece of data that comes in from any module gets logged here
        immediately. Before any processing. Before any analysis.
        The raw data gets locked first.
        
        Args:
            module:       Which module generated this (e.g. "m1_infrastructure")
            query:        Exactly what was asked (e.g. "dig +short A ssiloc.com")
            source:       Which database or protocol was queried (e.g. "DNS/system")
            response:     Exactly what came back, unmodified
            investigator: Who is running this investigation
            
        Returns:
            dict: The complete evidence entry including hash
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build the entry content to be hashed
        content = {
            "investigation_id": self.investigation_id,
            "sequence":         self.sequence,
            "timestamp":        timestamp,
            "investigator":     investigator,
            "module":           module,
            "query":            query,
            "source":           source,
            "response":         self._serialize(response),
            "previous_hash":    self.previous_hash,
        }

        # Hash the content
        entry_hash = self._hash(content)

        # Complete entry with its own hash
        entry = {**content, "entry_hash": entry_hash}

        # Write to disk immediately - before anything else
        self._write(entry)

        # Advance chain state
        self.previous_hash = entry_hash
        self.sequence += 1

        return entry

    def verify(self):
        """
        Verify the complete chain integrity.
        
        Reads every entry from disk and recomputes every hash.
        Any alteration after writing will cause a mismatch.
        
        Returns:
            dict: Verification result with details on any failures
        """
        if not self.chain_file.exists():
            return {
                "valid": False,
                "reason": "Chain file does not exist",
                "investigation_id": self.investigation_id
            }

        entries = self._read_all()

        if not entries:
            return {
                "valid": True,
                "entries_verified": 0,
                "investigation_id": self.investigation_id
            }

        failures = []
        previous_hash = "GENESIS"

        for i, entry in enumerate(entries):
            # Pull stored hash out before recomputing
            stored_hash = entry.pop("entry_hash", None)

            # Recompute hash from content
            computed_hash = self._hash(entry)

            # Check stored hash matches computed
            if stored_hash != computed_hash:
                failures.append({
                    "sequence": entry.get("sequence", i),
                    "reason": "Hash mismatch - entry was altered after writing",
                    "stored_hash": stored_hash,
                    "computed_hash": computed_hash
                })

            # Check chain link
            if entry.get("previous_hash") != previous_hash:
                failures.append({
                    "sequence": entry.get("sequence", i),
                    "reason": "Chain break - previous_hash does not match",
                    "expected": previous_hash,
                    "found": entry.get("previous_hash")
                })

            # Restore hash for next iteration
            entry["entry_hash"] = stored_hash
            previous_hash = stored_hash

        return {
            "valid": len(failures) == 0,
            "investigation_id": self.investigation_id,
            "entries_verified": len(entries),
            "failures": failures,
            "chain_file": str(self.chain_file),
            "verified_at": datetime.now(timezone.utc).isoformat()
        }

    def summary(self):
        """
        Return a human-readable summary of the investigation chain.
        
        Returns:
            dict: Investigation metadata and entry count by module
        """
        entries = self._read_all()

        if not entries:
            return {
                "investigation_id": self.investigation_id,
                "entries": 0,
                "modules": {},
                "chain_file": str(self.chain_file)
            }

        modules = {}
        for entry in entries:
            m = entry.get("module", "unknown")
            modules[m] = modules.get(m, 0) + 1

        return {
            "investigation_id": self.investigation_id,
            "entries": len(entries),
            "modules": modules,
            "started": entries[0].get("timestamp"),
            "last_entry": entries[-1].get("timestamp"),
            "chain_file": str(self.chain_file),
            "chain_valid": self.verify()["valid"]
        }

    def export(self, output_path=None):
        """
        Export the complete evidence chain as a single JSON file.
        Suitable for submission as a court exhibit.
        
        Args:
            output_path: Where to write the export. Defaults to
                         investigations/reports/{investigation_id}_evidence.json
                         
        Returns:
            str: Path to the exported file
        """
        entries = self._read_all()
        verification = self.verify()

        export_data = {
            "document_type": "FORENSIC_EVIDENCE_CHAIN",
            "tool": "Connect the Felons v1.0",
            "methodology": "SHA-256 chain of custody per NIST SP 800-86",
            "admissibility_basis": "Federal Rules of Evidence 901(b)(9)",
            "investigation_id": self.investigation_id,
            "chain_integrity": verification,
            "entries": entries,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

        if output_path is None:
            report_dir = Path("investigations/reports")
            report_dir.mkdir(parents=True, exist_ok=True)
            output_path = report_dir / f"{self.investigation_id}_evidence.json"

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        return str(output_path)

    # ─────────────────────────────────────────────────────────────
    # INTERNAL METHODS
    # ─────────────────────────────────────────────────────────────

    def _initialize(self):
        """Write the genesis entry for a new investigation."""
        genesis = {
            "investigation_id": self.investigation_id,
            "sequence":         0,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "investigator":     "system",
            "module":           "journal",
            "query":            "INVESTIGATION_INITIALIZED",
            "source":           "system",
            "response":         f"New investigation started: {self.investigation_id}",
            "previous_hash":    "GENESIS",
        }
        genesis_hash = self._hash(genesis)
        genesis["entry_hash"] = genesis_hash

        self._write(genesis)

        self.previous_hash = genesis_hash
        self.sequence = 1

    def _resume(self):
        """Resume an existing investigation by reading the current chain state."""
        entries = self._read_all()
        if entries:
            last = entries[-1]
            self.previous_hash = last.get("entry_hash", "GENESIS")
            self.sequence = last.get("sequence", 0) + 1

    def _hash(self, content):
        """
        Compute SHA-256 hash of content dictionary.
        
        Content is serialized to JSON with sorted keys before hashing
        to ensure consistent hash regardless of key ordering.
        """
        serialized = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _serialize(self, response):
        """
        Serialize any response type to a string-safe format.
        Handles strings, dicts, lists, bytes, and None.
        """
        if response is None:
            return "NULL"
        if isinstance(response, bytes):
            return response.decode("utf-8", errors="replace")
        if isinstance(response, (dict, list)):
            return json.dumps(response, default=str)
        return str(response)

    def _write(self, entry):
        """
        Append one entry to the chain file.
        
        Uses append mode so entries are never overwritten.
        Each entry is one JSON line (JSONL format).
        fsync ensures it's written to disk before continuing.
        """
        with open(self.chain_file, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _read_all(self):
        """Read all entries from the chain file."""
        entries = []
        if not self.chain_file.exists():
            return entries
        with open(self.chain_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries


# ─────────────────────────────────────────────────────────────────────
# CONVENIENCE FUNCTION
# ─────────────────────────────────────────────────────────────────────

def new_investigation():
    """
    Start a new investigation and return the journal.
    Prints the investigation ID so it can be referenced later.
    """
    journal = EvidenceJournal()
    print(f"[CTF] New investigation: {journal.investigation_id}")
    print(f"[CTF] Evidence chain: {journal.chain_file}")
    return journal


def resume_investigation(investigation_id):
    """
    Resume an existing investigation by ID.
    """
    journal = EvidenceJournal(investigation_id=investigation_id)
    result = journal.verify()
    if result["valid"]:
        print(f"[CTF] Resumed investigation: {investigation_id}")
        print(f"[CTF] Chain integrity: VERIFIED ({result['entries_verified']} entries)")
    else:
        print(f"[CTF] WARNING: Chain integrity FAILED for {investigation_id}")
        for failure in result["failures"]:
            print(f"  → {failure['reason']} at sequence {failure['sequence']}")
    return journal


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Evidence Journal Self-Test")
    print("=" * 60)

    # Use temp directory for test
    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        print(f"\nInvestigation ID: {journal.investigation_id}")

        # Log some test entries
        e1 = journal.log(
            module="m1_infrastructure",
            query="dig +short A ssiloc.com",
            source="DNS/system",
            response="192.0.2.88"
        )
        print(f"\nEntry 1 hash: {e1['entry_hash'][:16]}...")

        e2 = journal.log(
            module="m2_dns_email",
            query="whois ssiloc.com",
            source="WHOIS/verisign",
            response={"registrant_name": "John Smith", "registrant_email": "john@example.com"}
        )
        print(f"Entry 2 hash: {e2['entry_hash'][:16]}...")

        e3 = journal.log(
            module="m3_ownership",
            query="SEC EDGAR search: John Smith",
            source="SEC EDGAR API",
            response={"company": "Acme Corp LLC", "cik": "0001234567"}
        )
        print(f"Entry 3 hash: {e3['entry_hash'][:16]}...")

        # Verify chain integrity
        print("\n" + "-" * 40)
        print("Verifying chain integrity...")
        result = journal.verify()
        print(f"Chain valid: {result['valid']}")
        print(f"Entries verified: {result['entries_verified']}")

        # Summary
        print("\n" + "-" * 40)
        s = journal.summary()
        print(f"Summary: {s['entries']} entries across {len(s['modules'])} modules")
        for mod, count in s["modules"].items():
            print(f"  {mod}: {count} entries")

        # Test tamper detection
        print("\n" + "-" * 40)
        print("Testing tamper detection...")
        chain_file = journal.chain_file

        # Read chain
        with open(chain_file, "r") as f:
            lines = f.readlines()

        # Tamper with entry 2
        entry2 = json.loads(lines[2])
        entry2["response"] = "TAMPERED DATA"
        lines[2] = json.dumps(entry2) + "\n"

        # Write tampered chain back
        with open(chain_file, "w") as f:
            f.writelines(lines)

        # Verify should fail
        tamper_result = journal.verify()
        print(f"Chain valid after tampering: {tamper_result['valid']}")
        if not tamper_result["valid"]:
            print(f"Detected {len(tamper_result['failures'])} failure(s)")
            print(f"  → {tamper_result['failures'][0]['reason']}")

        print("\n" + "=" * 60)
        print("Self-test complete.")
        print("Evidence journal is ready.")
        print("=" * 60)
