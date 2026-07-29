#!/usr/bin/env python3
"""
CONNECT THE FELONS
Main Orchestrator

Usage:
  python main.py <input>                   # Single target
  python main.py <input1> <input2> ...     # Multiple targets
  python main.py --resume <investigation_id>
  python main.py --verify <investigation_id>
  python main.py --adb                     # Analyze own connected device

Examples:
  python main.py ssiloc.com
  python main.py 192.168.1.1
  python main.py "John Smith LLC"
  python main.py 356938035643809
  python main.py 8901260123456789013
  python main.py --adb
"""

import sys
import os
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from evidence_journal import EvidenceJournal
from modules.m0_input_router import InputRouter
from modules.m1_infrastructure import InfrastructureFingerprinter
from modules.m2_dns_email import EmailDNSForensics
from modules.m3_ownership import OwnershipTraverser
from modules.m4_reverse_infra import ReverseInfrastructureMapper
from modules.m5_device import DeviceIdentityForensics
from modules.m6_graph import AssociationGraph
from modules.m7_reconciliation import Reconciliation
from modules.m8_attribution import AttributionEngine


# ─────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║         CONNECT THE FELONS  ·  CTF Forensics v1.0        ║
║         Public OSINT Investigation Platform               ║
║         All findings logged to SHA-256 evidence chain     ║
╚═══════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────────────────────────────
# INVESTIGATION ENGINE
# ─────────────────────────────────────────────────────────────────────

class Investigation:
    """
    Coordinates a complete investigation from a single entry point.
    Every module shares the same evidence journal.
    """

    def __init__(self, investigation_id=None, base_dir=None,
                 github_token=None, hibp_key=None):
        """
        base_dir: writable root for the evidence chain files. Defaults to
        the cwd-relative "investigations/evidence_chains" (fine on
        Termux/desktop). Android has no writable cwd, so ctf_bridge.py
        passes the app's context.filesDir here instead.

        github_token / hibp_key: optional credentials for Module 4's
        GitHub commit search and HaveIBeenPwned breach lookups. Both
        modules work without them (GitHub falls back to the unauthenticated
        60 req/hr limit; HIBP reports it needs a key rather than failing).
        """
        self.journal   = EvidenceJournal(investigation_id=investigation_id, base_dir=base_dir)
        self.router    = InputRouter(journal=self.journal)
        self.infra     = InfrastructureFingerprinter(journal=self.journal)
        self.dns_email = EmailDNSForensics(journal=self.journal)
        self.ownership = OwnershipTraverser(journal=self.journal)
        self.device    = DeviceIdentityForensics(journal=self.journal)
        self.reverse_infra = ReverseInfrastructureMapper(
            journal=self.journal, github_token=github_token, hibp_key=hibp_key
        )
        self.reconciliation = Reconciliation(journal=self.journal)
        self.attribution     = AttributionEngine(journal=self.journal)
        try:
            self.graph = AssociationGraph(journal=self.journal)
        except ImportError:
            self.graph = None
        self.results   = {}

        print(f"\n[CTF] Investigation: {self.journal.investigation_id}")
        print(f"[CTF] Evidence chain: {self.journal.chain_file}")

    def run(self, targets, self_identifiers=None):
        """
        Run full investigation on a list of target strings.

        Detects each target type, routes to the correct modules,
        collects results, and prints a final summary.

        self_identifiers: optional list of identifiers the investigator
        has confirmed are their own (own email, phone, IMEI, etc). Used
        by Module 8 to separate self-owned artifacts from subject-owned
        ones. Safe to omit - Module 8 just won't have a SELF_OWNED bucket
        to sort into.
        """
        if isinstance(targets, str):
            targets = [targets]

        print(f"\n[CTF] Starting investigation on {len(targets)} target(s)")

        for target in targets:
            print(f"\n{'═' * 60}")
            print(f"Target: {target}")
            print(f"{'═' * 60}")

            # Route the input
            route = self.router.route(target)
            input_type = route.get("type")
            normalized = route.get("normalized", target)

            # Run appropriate modules
            if input_type in ("DOMAIN",):
                self._run_domain(normalized)

            elif input_type in ("IPV4", "IPV6"):
                self._run_ip(normalized)

            elif input_type in ("EMAIL",):
                self._run_email(normalized)

            elif input_type == "IMEI":
                self._run_imei(normalized)

            elif input_type == "ICCID":
                self._run_iccid(normalized)

            elif input_type == "MAC":
                self._run_mac(normalized)

            elif input_type == "SERIAL":
                self._run_serial(normalized)

            elif input_type == "PHONE":
                self._run_phone(normalized)

            elif input_type == "UNKNOWN":
                # Try as company name
                print(f"\n[CTF] Unknown input type - attempting corporate registry search")
                self._run_company(target)

            else:
                print(f"\n[CTF] No handler for input type: {input_type}")

        # Modules 6/7/8 operate on everything the run above collected -
        # no new queries, pure analysis of self.results.
        self._build_association_graph()
        self._run_reconciliation()
        self._run_attribution(self_identifiers or [])

        # Final summary
        self._print_summary()

        return self.results

    def run_adb(self):
        """Run ADB analysis on own connected device."""
        print(f"\n{'═' * 60}")
        print("ADB Device Analysis - Own Device")
        print(f"{'═' * 60}")

        result = self.device.analyze_own_device()
        self.results["adb_device"] = result

        # If we got an IMEI, run full IMEI analysis
        if result.get("imei"):
            print(f"\n[CTF] IMEI found, running full analysis...")
            self._run_imei(result["imei"])

        # If we got WiFi MAC, run OUI lookup
        if result.get("mac_wifi"):
            print(f"\n[CTF] WiFi MAC found, running OUI lookup...")
            self._run_mac(result["mac_wifi"])

        self._print_summary()
        return self.results

    # ─────────────────────────────────────────────────────────────────
    # MODULE RUNNERS
    # ─────────────────────────────────────────────────────────────────

    def _run_domain(self, domain):
        """Domain: infrastructure fingerprint + email/DNS forensics"""
        # Extract apex domain for email analysis
        parts = domain.split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        # Module 1: Infrastructure
        infra = self.infra.fingerprint_domain(domain)
        self.results[f"infra:{domain}"] = infra

        # Module 2: Email/DNS forensics (on apex domain)
        email_dns = self.dns_email.analyze(apex)
        self.results[f"email_dns:{apex}"] = email_dns

        # If registrant found, run ownership chain
        registrant = email_dns.get("whois", {}).get("registrant_org") or \
                     email_dns.get("whois", {}).get("registrant_name")
        if registrant:
            print(f"\n[CTF] Registrant found: {registrant} → tracing ownership chain")
            chain = self.ownership.trace(registrant)
            self.results[f"ownership:{registrant}"] = chain

        # Module 4: extend attribution on the registrant email WHOIS just
        # surfaced - this is exactly the "identifier already surfaced
        # during an investigation" use case M4 was built for.
        registrant_email = email_dns.get("whois", {}).get("registrant_email")
        if registrant_email:
            print(f"\n[CTF] Registrant email found: {registrant_email} → reverse infrastructure mapping")
            reverse = self.reverse_infra.map_email(registrant_email)
            self.results[f"reverse_infra:{registrant_email}"] = reverse

    def _run_ip(self, ip):
        """IP address: infrastructure fingerprint only"""
        infra = self.infra.fingerprint_ip(ip)
        self.results[f"infra:{ip}"] = infra

        # If reverse DNS gives domain names, analyze those too
        rdns = infra.get("reverse_dns", {}).get("hostnames", [])
        for hostname in rdns[:2]:
            if "." in hostname:
                print(f"\n[CTF] Reverse DNS → {hostname}: running domain analysis")
                self._run_domain(hostname)

    def _run_email(self, email):
        """Email: DNS/email forensics on the domain part"""
        domain = email.split("@")[-1]
        email_dns = self.dns_email.analyze(domain)
        self.results[f"email_dns:{domain}"] = email_dns

    def _run_imei(self, imei):
        """IMEI: device identity analysis"""
        result = self.device.analyze_imei(imei)
        self.results[f"imei:{imei}"] = result

    def _run_iccid(self, iccid):
        """ICCID: log and note for carrier request"""
        self.journal.log(
            module="main",
            query=f"ICCID: {iccid}",
            source="investigator-input",
            response=f"ICCID logged. Carrier HLR lookup requires legal process. Generate carrier request letter via report engine."
        )
        print(f"\n[CTF] ICCID logged to evidence chain.")
        print(f"  Carrier lookup requires formal legal request to carrier.")
        print(f"  Generate the demand letter:")
        print(f"    from report_engine import ReportEngine")
        print(f"    ReportEngine(self.journal).carrier_demand(carrier_name=..., account_holder=...,")
        print(f"        phone_number='{iccid}', issue_description=..., requester_address=...)")
        self.results[f"iccid:{iccid}"] = {"iccid": iccid, "note": "Carrier HLR lookup required"}

    def _run_mac(self, mac):
        """MAC address: OUI manufacturer lookup"""
        result = self.device.analyze_mac(mac)
        self.results[f"mac:{mac}"] = result

    def _run_serial(self, serial):
        """Serial number: FCC equipment lookup"""
        self.journal.log(
            module="main",
            query=f"SERIAL: {serial}",
            source="investigator-input",
            response=f"Serial number logged for FCC and manufacturer lookup."
        )
        print(f"\n[CTF] Serial number logged: {serial}")
        print(f"  FCC equipment search: https://apps.fcc.gov/oetcf/eas")
        self.results[f"serial:{serial}"] = {"serial": serial}

    def _run_phone(self, phone):
        """Phone number: log, generate carrier demand"""
        self.journal.log(
            module="main",
            query=f"PHONE: {phone}",
            source="investigator-input",
            response=f"Phone number logged. Carrier CPNI disclosure requires legal demand letter."
        )
        print(f"\n[CTF] Phone number logged: {phone}")
        print(f"  CPNI disclosure: file FCC complaint or send formal carrier demand")
        print(f"  Generate the demand letter:")
        print(f"    from report_engine import ReportEngine")
        print(f"    ReportEngine(self.journal).carrier_demand(carrier_name=..., account_holder=...,")
        print(f"        phone_number='{phone}', issue_description=..., requester_address=...)")
        self.results[f"phone:{phone}"] = {"phone": phone}

    def _run_company(self, name):
        """Company/person name: ownership chain traversal"""
        result = self.ownership.trace(name)
        self.results[f"ownership:{name}"] = result

    # ─────────────────────────────────────────────────────────────────
    # MODULES 6/7/8 - CROSS-CUTTING ANALYSIS
    # ─────────────────────────────────────────────────────────────────
    # These run once at the end of run(), after every target has been
    # processed. They don't issue new queries - they organize and score
    # what the module runners above already found and logged.

    def _build_association_graph(self):
        """Module 6: build the entity graph from everything collected."""
        if not self.graph:
            print(f"\n[CTF] Association graph skipped: networkx not installed")
            return
        summary = self.graph.from_investigation_results(self.results)
        self.results["_graph_summary"] = summary
        print(f"\n[CTF/M6] Association graph: {summary['total_nodes']} nodes, "
              f"{summary['total_edges']} edges, {summary['clusters']} cluster(s)")

    def _run_reconciliation(self):
        """
        Module 7: check whether the geography, timeline, identity count,
        and infrastructure mix found above actually hold together.

        Every input here traces back to a field a module already put in
        self.results - nothing is guessed to make the check run.
        """
        locations, events, identities, infra_types = [], [], [], []

        for key, result in self.results.items():
            if not isinstance(result, dict):
                continue

            # Geography: IP geolocations found by M1
            for ip, ip_data in result.get("ips", {}).items():
                geo = ip_data.get("geolocation", {})
                if geo.get("latitude") is not None and geo.get("longitude") is not None:
                    locations.append({
                        "label": f"ip_geolocation:{ip}",
                        "lat": geo["latitude"],
                        "lon": geo["longitude"],
                    })

            # Timeline: domain registration date + earliest certificate, from M2
            whois = result.get("whois", {})
            if whois.get("created"):
                events.append({"label": f"registered:{result.get('domain')}", "timestamp": whois["created"]})
            certs = result.get("certificates", {})
            if certs.get("earliest_cert"):
                events.append({"label": f"certificate_issued:{result.get('domain')}", "timestamp": certs["earliest_cert"]})

            # Identity: registrant name from M2, natural persons from M3
            if whois.get("registrant_name"):
                identities.append(whois["registrant_name"])
            for person in result.get("natural_persons", []):
                identities.append(person["name"])

            # Infrastructure mix, from M1
            for ip, ip_data in result.get("ips", {}).items():
                if ip_data.get("infrastructure_type"):
                    infra_types.append(ip_data["infrastructure_type"])

        recon = self.reconciliation.reconcile(
            locations=locations, events=events,
            identities=identities, infra_types=infra_types,
        )
        self.results["_reconciliation"] = recon

    def _run_attribution(self, self_identifiers):
        """
        Module 8: separate self-owned from subject-owned artifacts and
        score relationship hypotheses.

        subject_identifiers and observed_signals are both derived from
        findings already sitting in self.results - each signal below is
        only included if the module that would confirm it actually
        returned a hit.
        """
        subject_identifiers = set()
        signals = set()
        natural_person_count = 0

        for key, result in self.results.items():
            if not isinstance(result, dict):
                continue

            domain = result.get("domain")
            if domain:
                subject_identifiers.add(domain)
                if domain.endswith(".gov") or domain.endswith(".mil"):
                    signals.add("government_tld")

            for ip in result.get("ips", {}):
                subject_identifiers.add(ip)

            whois = result.get("whois", {})
            if whois.get("registrant_email"):
                subject_identifiers.add(whois["registrant_email"])

            auth = result.get("email_auth", {})
            if auth.get("score", 0) >= 50:
                signals.add("compliance_posture_present")

            # Ownership chain findings (M3)
            if "chain" in result and "query" in result:
                chain = result["chain"]
                if chain.get("entity_type") in ("PRIVATE_COMPANY", "PUBLIC_COMPANY"):
                    signals.add("registered_corporation")
                if chain.get("entity_type") == "NATURAL_PERSON" and chain.get("depth", 0) == 0:
                    signals.add("no_corporate_structure")
                if result.get("depth_reached", 0) > 2:
                    signals.add("shell_company_chain_depth_gt_2")
                if result.get("ofac_flags"):
                    signals.add("ofac_match")
                if result.get("offshore_flags"):
                    signals.add("offshore_leak_match")
                for person in result.get("natural_persons", []):
                    subject_identifiers.add(person["name"])
                    natural_person_count += 1

        if natural_person_count == 1:
            signals.add("single_named_individual")

        recon = self.results.get("_reconciliation", {})
        if recon.get("identity", {}).get("classification") == "ANOMALOUS":
            signals.add("identity_fragmentation_high")

        attribution = self.attribution.differentiate(
            artifacts=list(subject_identifiers),
            self_identifiers=self_identifiers,
            subject_identifiers=list(subject_identifiers),
            observed_signals=list(signals),
        )
        self.results["_attribution"] = attribution

    # ─────────────────────────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────────────────────────

    def _print_summary(self):
        """Print investigation summary and evidence chain status."""
        print(f"\n{'═' * 60}")
        print("INVESTIGATION SUMMARY")
        print(f"{'═' * 60}")

        print(f"Investigation ID: {self.journal.investigation_id}")
        print(f"Chain file:       {self.journal.chain_file}")

        # Verify chain
        v = self.journal.verify()
        status = "✓ VALID" if v["valid"] else "✗ COMPROMISED"
        print(f"Evidence chain:   {v['entries_verified']} entries - {status}")

        # Red flags
        flags = self._collect_flags()
        if flags:
            print(f"\nFlags ({len(flags)}):")
            for flag in flags:
                print(f"  🚩 {flag}")

        # Key findings
        findings = self._collect_findings()
        if findings:
            print(f"\nKey findings:")
            for finding in findings:
                print(f"  → {finding}")

        print(f"\nExport evidence: python main.py --export {self.journal.investigation_id}")
        print(f"{'═' * 60}")

    def _collect_flags(self):
        """Collect all red flags from all module results."""
        flags = []
        for key, result in self.results.items():
            # Email posture flags
            if isinstance(result, dict):
                auth = result.get("email_auth", {})
                if auth.get("posture") in ("ABSENT", "MINIMAL"):
                    flags.append(f"Email authentication: {auth.get('posture')} on {result.get('domain')}")
                for flag in auth.get("flags", []):
                    flags.append(flag)

                # Spamhaus
                spam = result.get("spamhaus", {})
                if spam.get("listed"):
                    flags.append(f"Spamhaus DBL: {spam.get('category')} - {result.get('domain')}")

                # URLhaus
                uh = result.get("urlhaus", {})
                if uh.get("listed"):
                    flags.append(f"URLhaus: malicious domain - {result.get('domain')}")

                # OFAC
                ownership = result.get("chain", {})
                if isinstance(ownership, dict) and ownership.get("ofac_flags"):
                    for f in ownership["ofac_flags"]:
                        flags.append(f"OFAC SDN MATCH: {f.get('entity')}")

                # MDM indicators
                mdm = result.get("mdm_indicators", [])
                for ind in mdm:
                    flags.append(f"MDM: {ind}")

        return flags

    def _collect_findings(self):
        """Collect key findings for summary."""
        findings = []
        for key, result in self.results.items():
            if not isinstance(result, dict):
                continue

            # Infrastructure locations
            summary = result.get("summary", {})
            if summary.get("locations"):
                findings.append(f"Infrastructure located: {', '.join(summary['locations'])}")
            if summary.get("hosting_providers"):
                findings.append(f"Hosted by: {', '.join(summary['hosting_providers'])}")

            # Registrant
            whois = result.get("whois", {})
            if whois.get("registrant_name"):
                findings.append(f"Registrant: {whois['registrant_name']}")
            if whois.get("registrant_email"):
                findings.append(f"Registrant email: {whois['registrant_email']}")

            # Natural persons in ownership chain
            persons = result.get("natural_persons", [])
            for p in persons:
                findings.append(f"Natural person: {p['name']} ({p.get('role', 'owner')})")

            # Device info
            if result.get("model"):
                findings.append(f"Device: {result.get('manufacturer')} {result.get('model')}")

        return findings

    def export(self):
        """Export complete investigation as JSON."""
        path = self.journal.export()
        print(f"\n[CTF] Evidence exported: {path}")
        return path


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Connect the Felons - OSINT Investigation Platform"
    )
    parser.add_argument("targets", nargs="*",
                        help="Target(s) to investigate (domain, IP, email, IMEI, etc.)")
    parser.add_argument("--adb", action="store_true",
                        help="Analyze own connected Android device via ADB")
    parser.add_argument("--resume", metavar="ID",
                        help="Resume existing investigation by ID")
    parser.add_argument("--verify", metavar="ID",
                        help="Verify evidence chain integrity for investigation ID")
    parser.add_argument("--export", metavar="ID",
                        help="Export investigation to JSON file")
    parser.add_argument("--sms", metavar="PHONE",
                        help="Generate SMS loop-back test for SIM cloning detection")

    args = parser.parse_args()

    # Verify only
    if args.verify:
        journal = EvidenceJournal(investigation_id=args.verify)
        result = journal.verify()
        print(f"Investigation: {args.verify}")
        print(f"Entries:       {result['entries_verified']}")
        print(f"Chain valid:   {result['valid']}")
        if result.get("failures"):
            print(f"Failures:")
            for f in result["failures"]:
                print(f"  Sequence {f['sequence']}: {f['reason']}")
        return

    # Export only
    if args.export:
        inv = Investigation(investigation_id=args.export)
        path = inv.export()
        return

    # SMS test only
    if args.sms:
        inv = Investigation()
        test = inv.device.sms_loopback(args.sms)
        print(f"\nSMS Loop-back Test prepared for: {args.sms}")
        print(f"Legal note: {test['legal_note']}")
        for step in test["instructions"]:
            print(f"  {step}")
        return

    # Start or resume investigation
    investigation_id = args.resume or None
    inv = Investigation(investigation_id=investigation_id)

    # Run ADB analysis
    if args.adb:
        inv.run_adb()
        return

    # Require at least one target
    if not args.targets:
        parser.print_help()
        print("\nExamples:")
        print("  python main.py ssiloc.com")
        print("  python main.py 192.0.2.88")
        print("  python main.py test@domain.com")
        print("  python main.py 356938035643809")
        print("  python main.py --adb")
        return

    inv.run(args.targets)


if __name__ == "__main__":
    main()
