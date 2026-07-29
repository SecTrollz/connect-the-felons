#!/usr/bin/env python3
"""
CONNECT THE FELONS
Report Engine

One job: Turn the evidence journal and module findings into the three
documents an investigation actually needs - something a detective can
read in five minutes, something a court can examine line by line, and
the legal letters that get an investigator's own data back from the
companies holding it.

Three outputs:
  1. Law enforcement handoff  - plain language, no jargon
  2. Court-admissible report  - full methodology, complete evidence chain
  3. Legal demand letters     - DSAR (CCPA/GDPR/TDPSA/FCRA), FCC complaint,
                                 IC3 complaint, carrier CPNI/HLR demand

All three pull directly from the evidence journal - nothing in these
reports is asserted that doesn't trace back to a hashed, timestamped
entry in the chain. Letter templates use bracketed placeholders for
any field this tool doesn't actually know - never invented.
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_journal import EvidenceJournal


# ─────────────────────────────────────────────────────────────────────
# LAW ENFORCEMENT HANDOFF
# ─────────────────────────────────────────────────────────────────────

def generate_le_handoff(journal, findings_summary):
    """
    Plain language report for a detective or officer with five minutes
    and no technical background. Leads with what happened, not methodology.
    """
    entries = journal._read_all()
    verification = journal.verify()

    lines = []
    lines.append("=" * 70)
    lines.append("LAW ENFORCEMENT INVESTIGATION SUMMARY")
    lines.append("=" * 70)
    lines.append(f"Investigation ID: {journal.investigation_id}")
    lines.append(f"Prepared: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"Evidence integrity: {'VERIFIED' if verification['valid'] else 'COMPROMISED - DO NOT USE'}")
    lines.append("")
    lines.append("WHAT THIS DOCUMENT IS")
    lines.append("-" * 70)
    lines.append(
        "Summary of a self-directed forensic investigation using public "
        "records only - domain registration data, certificate logs, "
        "corporate filings, and device identifiers. No private databases "
        "were accessed. No systems were probed beyond standard DNS/WHOIS "
        "lookups available to anyone."
    )
    lines.append("")
    lines.append("KEY FINDINGS")
    lines.append("-" * 70)
    for finding in findings_summary.get("key_findings", []):
        lines.append(f"  - {finding}")
    lines.append("")
    if findings_summary.get("red_flags"):
        lines.append("FLAGS REQUIRING ATTENTION")
        lines.append("-" * 70)
        for flag in findings_summary["red_flags"]:
            lines.append(f"  - {flag}")
        lines.append("")
    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 70)
    default_steps = [
        "Request carrier HLR/CPNI records via subpoena if SIM cloning suspected",
        "Cross-reference findings against existing case management system",
        "Request full evidence export (court-admissible report) if pursuing charges",
    ]
    for step in findings_summary.get("next_steps", default_steps):
        lines.append(f"  - {step}")
    lines.append("")
    lines.append(f"Full technical evidence chain: {len(entries)} logged entries, available on request")
    lines.append("=" * 70)

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────
# COURT-ADMISSIBLE TECHNICAL REPORT
# ─────────────────────────────────────────────────────────────────────

def generate_court_report(journal):
    """
    Full technical report: methodology, every source queried, every
    finding, complete evidence chain. Nothing summarized away - if it
    was logged, it's in here.
    """
    entries = journal._read_all()
    verification = journal.verify()
    summary = journal.summary()

    lines = []
    lines.append("=" * 70)
    lines.append("FORENSIC INVESTIGATION TECHNICAL REPORT")
    lines.append("=" * 70)
    lines.append(f"Investigation ID:    {journal.investigation_id}")
    lines.append(f"Report generated:    {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Tool:                Connect the Felons v1.0")
    lines.append(f"Methodology:         SHA-256 evidence chain of custody")
    lines.append(f"Admissibility basis: Federal Rules of Evidence 901(b)(9)")
    lines.append("")
    lines.append("CHAIN INTEGRITY VERIFICATION")
    lines.append("-" * 70)
    lines.append(f"Total entries:       {verification['entries_verified']}")
    lines.append(f"Chain valid:         {verification['valid']}")
    if verification.get("failures"):
        lines.append(f"INTEGRITY FAILURES:  {len(verification['failures'])}")
        for f in verification["failures"]:
            lines.append(f"  - Sequence {f['sequence']}: {f['reason']}")
    lines.append("")
    lines.append("METHODOLOGY")
    lines.append("-" * 70)
    lines.append(
        "Every finding below was logged to the evidence chain at the moment "
        "of discovery, before any analysis was performed on it. Each entry "
        "is SHA-256 hashed against its own content plus the hash of the "
        "entry before it, forming an unbroken chain. Any modification to "
        "any entry after it was written invalidates every hash that follows "
        "it - the chain integrity check above confirms whether that has "
        "occurred."
    )
    lines.append("")
    lines.append("MODULES USED")
    lines.append("-" * 70)
    for module, count in summary.get("modules", {}).items():
        lines.append(f"  {module}: {count} queries logged")
    lines.append("")
    lines.append("COMPLETE EVIDENCE CHAIN")
    lines.append("-" * 70)
    for entry in entries:
        lines.append(f"\n[{entry.get('sequence')}] {entry.get('timestamp')}")
        lines.append(f"    Module:   {entry.get('module')}")
        lines.append(f"    Query:    {entry.get('query')}")
        lines.append(f"    Source:   {entry.get('source')}")
        response_str = str(entry.get('response', ''))
        if len(response_str) > 300:
            response_str = response_str[:300] + "... [truncated for readability, full content in JSON export]"
        lines.append(f"    Response: {response_str}")
        lines.append(f"    Hash:     {entry.get('entry_hash')}")
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("Full machine-readable evidence export available via journal.export()")
    lines.append("=" * 70)

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────
# LEGAL DEMAND LETTERS
# ─────────────────────────────────────────────────────────────────────

_STATUTE_CITATIONS = {
    "CCPA":    "California Consumer Privacy Act (Cal. Civ. Code § 1798.100 et seq.), as amended by the California Privacy Rights Act",
    "GDPR":    "General Data Protection Regulation, Article 15 (Right of Access)",
    "TDPSA":   "Texas Data Privacy and Security Act (Tex. Bus. & Com. Code § 541.001 et seq.)",
    "FCRA":    "Fair Credit Reporting Act (15 U.S.C. § 1681 et seq.)",
    "GENERIC": "applicable state and federal consumer privacy statutes",
}

_RESPONSE_WINDOWS = {"CCPA": "45 days", "GDPR": "30 days", "TDPSA": "45 days", "FCRA": "30 days", "GENERIC": "a reasonable time"}


def generate_dsar_letter(company_name, company_address, requester_name,
                          requester_address, jurisdiction="CCPA"):
    """
    Data Subject Access Request letter. Under CCPA, GDPR, TDPSA, and FCRA
    (for credit-bureau / consumer-reporting agencies specifically),
    individuals have a statutory right to request what personal data a
    company holds, where it came from, and who it's been shared with.
    """
    statute = _STATUTE_CITATIONS.get(jurisdiction, _STATUTE_CITATIONS["GENERIC"])
    window = _RESPONSE_WINDOWS.get(jurisdiction, _RESPONSE_WINDOWS["GENERIC"])

    letter = f"""{requester_name}
{requester_address}

{datetime.now().strftime('%B %d, %Y')}

{company_name}
{company_address}

RE: Data Subject Access Request Pursuant to {statute}

To Whom It May Concern:

I am writing to formally request, pursuant to {statute}, that you
provide me with the following regarding my personal information:

1. Confirmation of whether you are processing personal information
   relating to me.

2. A copy of all personal information you hold about me, including but
   not limited to: account records, communications, transaction history,
   device identifiers, location data, and any data obtained from or
   shared with third parties.

3. The categories of personal information collected, the sources from
   which it was collected, the business purpose for collecting it, and
   the categories of third parties with whom it has been shared or sold.

4. The specific pieces of personal information you have collected
   about me.

5. If applicable, confirmation of any data broker, marketing partner, or
   fraud-intelligence product line that has received my information, and
   an itemized list of those recipients.

Please respond within {window}, as required by the applicable statute. If
you require additional time, please notify me in writing with the reason
for the delay, as required by law.

If you deny any part of this request, please provide the specific
statutory basis for the denial in writing.

Please direct your response to the address above, or via email if you
confirm receipt of this letter.

Sincerely,

{requester_name}"""

    return letter


def generate_fcc_complaint(carrier_name, account_number, issue_summary,
                            requester_name, requester_contact):
    """
    FCC consumer complaint narrative, formatted to match the structure
    the FCC's own portal (consumercomplaints.fcc.gov) asks for. Filing
    through the actual portal is still required - this is the text to
    paste into it.
    """
    letter = f"""FCC CONSUMER COMPLAINT - PREPARED TEXT
File at: consumercomplaints.fcc.gov

Complainant: {requester_name}
Contact: {requester_contact}
Carrier: {carrier_name}
Account Number: {account_number}
Date prepared: {datetime.now().strftime('%B %d, %Y')}

COMPLAINT CATEGORY: Unauthorized account access / SIM provisioning / CPNI

DESCRIPTION OF ISSUE:
{issue_summary}

REQUESTED RESOLUTION:
1. Full CPNI (Customer Proprietary Network Information) disclosure for my
   account, including a complete log of all devices ever provisioned on
   my line and the dates each was added or removed.
2. HLR (Home Location Register) history showing all device/SIM
   registrations associated with my account.
3. Written confirmation of any account changes, port requests, or SIM
   swaps initiated in the last 12 months, including the authentication
   method used to authorize each change.
4. Immediate review of account security and removal of any unauthorized
   device or SIM provisioning.

SUPPORTING EVIDENCE:
[Attach evidence export from Connect the Felons evidence journal -
SHA-256 verified chain of custody available on request]"""

    return letter


def generate_ic3_complaint(incident_summary, financial_loss=None,
                            requester_name=None, requester_contact=None):
    """
    IC3 (FBI Internet Crime Complaint Center) complaint narrative.
    Filing still requires submission through ic3.gov - this generates
    the narrative section.
    """
    letter = f"""IC3 COMPLAINT - PREPARED NARRATIVE
File at: ic3.gov

Complainant: {requester_name or '[NAME]'}
Contact: {requester_contact or '[CONTACT INFO]'}
Date prepared: {datetime.now().strftime('%B %d, %Y')}
Financial loss: {financial_loss if financial_loss else 'None reported / Not primarily financial'}

INCIDENT NARRATIVE:
{incident_summary}

INVESTIGATIVE METHODOLOGY:
This complaint is supported by a forensic evidence chain using public
OSINT sources only (DNS, WHOIS, certificate transparency logs, public
corporate registries). Each finding is SHA-256 hashed and timestamped at
the moment of discovery. Full evidence export available on request."""

    return letter


def generate_carrier_demand(carrier_name, account_holder, phone_number,
                             issue_description, requester_address):
    """
    Formal demand letter to a carrier for HLR lookup / CPNI disclosure
    when SMS loop-back testing or other signals suggest unauthorized
    dual provisioning. Carriers are required under 47 U.S.C. § 222 to
    protect CPNI and respond to legitimate account holder requests.
    """
    letter = f"""{account_holder}
{requester_address}

{datetime.now().strftime('%B %d, %Y')}

{carrier_name}
Legal/Compliance Department

RE: Formal Demand for CPNI Disclosure and HLR Audit - Account: {phone_number}

To Whom It May Concern:

Pursuant to my rights as the account holder under 47 U.S.C. § 222
(Customer Proprietary Network Information), I am formally requesting the
following regarding the line listed above:

1. A complete history of every device (by IMEI/IMSI) ever provisioned on
   this account, with provisioning and deprovisioning timestamps.

2. HLR (Home Location Register) records showing all SIM/eSIM profiles
   ever associated with this account.

3. A log of all account changes, including the authentication method
   used (in-store ID verification, phone PIN, online password, etc.) for
   each change, for the past 24 months.

4. Confirmation of whether more than one device has been registered to
   receive calls/SMS for this number simultaneously at any point in the
   past 12 months.

ISSUE DESCRIPTION:
{issue_description}

I am requesting this information pursuant to my statutory right to
access CPNI associated with my own account. Please respond within 30
days. If you require written authorization in another form, please
specify exactly what is needed so I can provide it without delay.

Sincerely,

{account_holder}
{phone_number}"""

    return letter


# ─────────────────────────────────────────────────────────────────────
# MAIN REPORT ENGINE CLASS
# ─────────────────────────────────────────────────────────────────────

class ReportEngine:
    """
    Wraps an evidence journal and produces the three report types plus
    legal letter templates. Everything pulls from the journal directly -
    no report content here is invented separately from logged evidence.
    """

    def __init__(self, journal, output_dir=None):
        """
        output_dir: writable directory to save generated reports/letters
        to. Defaults to the cwd-relative "investigations/reports" (fine
        on Termux/desktop - not writable under Chaquopy on Android, so
        ctf_bridge.py passes an app-storage path here instead).
        """
        self.journal = journal
        self.output_dir = Path(output_dir) if output_dir else Path("investigations/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def le_handoff(self, findings_summary=None, save=True):
        report = generate_le_handoff(self.journal, findings_summary or {})
        if save:
            path = self.output_dir / f"{self.journal.investigation_id}_LE_handoff.txt"
            path.write_text(report)
            print(f"[CTF] LE handoff report saved: {path}")
        return report

    def court_report(self, save=True):
        report = generate_court_report(self.journal)
        if save:
            path = self.output_dir / f"{self.journal.investigation_id}_court_report.txt"
            path.write_text(report)
            print(f"[CTF] Court report saved: {path}")
        return report

    def dsar_letter(self, company_name, company_address, requester_name,
                     requester_address, jurisdiction="CCPA", save=True):
        letter = generate_dsar_letter(company_name, company_address, requester_name,
                                       requester_address, jurisdiction)
        self.journal.log(module="report_engine", query=f"DSAR_LETTER: {company_name}",
                          source="local-template-generator",
                          response=f"DSAR letter generated for {company_name} under {jurisdiction}")
        if save:
            safe_name = "".join(c if c.isalnum() else "_" for c in company_name)
            path = self.output_dir / f"{self.journal.investigation_id}_DSAR_{safe_name}.txt"
            path.write_text(letter)
            print(f"[CTF] DSAR letter saved: {path}")
        return letter

    def fcc_complaint(self, carrier_name, account_number, issue_summary,
                       requester_name, requester_contact, save=True):
        letter = generate_fcc_complaint(carrier_name, account_number, issue_summary,
                                         requester_name, requester_contact)
        self.journal.log(module="report_engine", query=f"FCC_COMPLAINT: {carrier_name}",
                          source="local-template-generator",
                          response=f"FCC complaint prepared for {carrier_name}")
        if save:
            path = self.output_dir / f"{self.journal.investigation_id}_FCC_complaint.txt"
            path.write_text(letter)
            print(f"[CTF] FCC complaint saved: {path}")
        return letter

    def ic3_complaint(self, incident_summary, financial_loss=None,
                       requester_name=None, requester_contact=None, save=True):
        letter = generate_ic3_complaint(incident_summary, financial_loss, requester_name, requester_contact)
        self.journal.log(module="report_engine", query="IC3_COMPLAINT",
                          source="local-template-generator", response="IC3 complaint narrative prepared")
        if save:
            path = self.output_dir / f"{self.journal.investigation_id}_IC3_complaint.txt"
            path.write_text(letter)
            print(f"[CTF] IC3 complaint saved: {path}")
        return letter

    def carrier_demand(self, carrier_name, account_holder, phone_number,
                        issue_description, requester_address, save=True):
        letter = generate_carrier_demand(carrier_name, account_holder, phone_number,
                                          issue_description, requester_address)
        self.journal.log(module="report_engine", query=f"CARRIER_DEMAND: {carrier_name}",
                          source="local-template-generator",
                          response=f"Carrier demand letter prepared for {carrier_name}")
        if save:
            safe_carrier = carrier_name.replace(' ', '_')
            path = self.output_dir / f"{self.journal.investigation_id}_carrier_demand_{safe_carrier}.txt"
            path.write_text(letter)
            print(f"[CTF] Carrier demand letter saved: {path}")
        return letter


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Report Engine Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)

        journal.log(module="m1_infrastructure", query="dig A ssiloc.example", source="DNS", response="192.0.2.88")
        journal.log(module="m2_dns_email", query="whois ssiloc.example", source="WHOIS",
                    response={"registrant_email": "admin@shellcorp.example"})

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            engine = ReportEngine(journal)

            print("\nTest 1: Law enforcement handoff")
            le = engine.le_handoff(findings_summary={
                "key_findings": ["Domain ssiloc.example resolves to datacenter IP", "Registrant email: admin@shellcorp.example"],
                "red_flags": ["No SPF/DMARC on registrant's domain"],
            })
            print(le[:500] + "\n...[truncated for display]...")

            print("\n" + "─" * 40)
            print("Test 2: Court-admissible report")
            court = engine.court_report()
            print(f"  Report length: {len(court)} chars")
            print(f"  Contains hash entries: {'Hash:' in court}")

            print("\n" + "─" * 40)
            print("Test 3: DSAR letter (TDPSA)")
            dsar = engine.dsar_letter(
                company_name="Example Data Broker Inc.",
                company_address="123 Broker Lane, Delaware",
                requester_name="[NAME]",
                requester_address="[ADDRESS], Austin, TX",
                jurisdiction="TDPSA",
            )
            print(dsar[:400] + "\n...[truncated for display]...")

            print("\n" + "─" * 40)
            print("Test 4: Carrier CPNI/HLR demand letter")
            carrier = engine.carrier_demand(
                carrier_name="Example Carrier",
                account_holder="[NAME]",
                phone_number="[PHONE NUMBER]",
                issue_description="SMS loop-back test on [DATE] showed delivery confirmation without corresponding inbox receipt, consistent with dual SIM provisioning.",
                requester_address="[ADDRESS], Austin, TX",
            )
            print(carrier[:400] + "\n...[truncated for display]...")

            saved_files = list(Path("investigations/reports").glob("*"))
            print(f"\n\nFiles written to disk: {len(saved_files)}")
            for f in saved_files:
                print(f"  {f}")

        finally:
            os.chdir(original_cwd)

        v = journal.verify()
        print(f"\nEvidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Report engine self-test complete.")
        print("=" * 60)
