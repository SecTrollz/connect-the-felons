#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 8 - Victim-Subject Differentiation & Attribution Hypotheses

One job: Once an investigation has surfaced a pile of domains, emails,
companies, and devices, sort out which belong to the person being
investigated FOR (who provided their own identifiers to compare against)
and which belong to whatever's being investigated.

This module produces hypotheses, not verdicts. It scores four competing
explanations for what's going on and shows the evidence behind each
score. Every output here is meant to go into a report that a human -
an investigator, a lawyer, a detective - reviews and verifies before
anyone acts on it. Nothing in this module asserts a specific named
person is guilty of anything. It organizes evidence into a structure a
human can evaluate, and every signal that feeds a hypothesis score has
to trace back to an actual finding from an earlier module - nothing
here is guessed.
"""

import os
import sys
from datetime import datetime, timezone

try:
    from dateutil import parser as date_parser
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal


def _parse_timestamp(ts):
    if DATEUTIL_AVAILABLE:
        return date_parser.parse(ts)
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ─────────────────────────────────────────────────────────────────────
# ARTIFACT CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────

class ArtifactOwner:
    SELF_OWNED    = "SELF_OWNED"     # Matches an identifier the investigator
                                       # provided as their own
    SUBJECT_OWNED = "SUBJECT_OWNED"   # Matches an identifier already
                                       # established as belonging to the
                                       # thing under investigation
    OVERLAP       = "OVERLAP"         # Matches both - worth a second look
    NEUTRAL       = "NEUTRAL"         # Matches neither - background noise


def classify_artifact(artifact, self_identifiers, subject_identifiers):
    """
    Pure set-membership check. self_identifiers is the list the
    investigator explicitly provides as "these are mine" (their own
    email, phone, IMEI). subject_identifiers is whatever's already been
    established as belonging to the thing under investigation by
    earlier modules. Neither list is guessed - both come from the
    investigator's own input or prior module findings.
    """
    artifact_norm  = str(artifact).strip().lower()
    self_norm      = {str(v).strip().lower() for v in self_identifiers}
    subject_norm   = {str(s).strip().lower() for s in subject_identifiers}

    in_self    = artifact_norm in self_norm
    in_subject = artifact_norm in subject_norm

    if in_self and in_subject:
        return ArtifactOwner.OVERLAP
    if in_self:
        return ArtifactOwner.SELF_OWNED
    if in_subject:
        return ArtifactOwner.SUBJECT_OWNED
    return ArtifactOwner.NEUTRAL


def classify_all(artifacts, self_identifiers, subject_identifiers):
    """Classify a full list of artifacts at once."""
    results = [
        {"artifact": a, "classification": classify_artifact(a, self_identifiers, subject_identifiers)}
        for a in artifacts
    ]

    counts = {}
    for r in results:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1

    overlap_items = [r["artifact"] for r in results if r["classification"] == ArtifactOwner.OVERLAP]

    return {
        "classified": results,
        "counts": counts,
        "overlap_items": overlap_items,
        "overlap_note": (
            "Items appearing in both lists deserve specific attention - "
            "either coincidental reuse of common infrastructure, or a "
            "genuine link worth investigating further."
        ) if overlap_items else None,
    }


# ─────────────────────────────────────────────────────────────────────
# RELATIONSHIP HYPOTHESES
# ─────────────────────────────────────────────────────────────────────

class Hypothesis:
    PERSONAL_ADVERSARY  = "PERSONAL_ADVERSARY"   # A specific individual, personal motive
    CORPORATE_ACTOR     = "CORPORATE_ACTOR"      # A registered business, commercial motive
    CRIMINAL_ENTERPRISE = "CRIMINAL_ENTERPRISE"  # Organized fraud, multi-entity structure
    STATE_LEA            = "STATE_LEA"           # Government or law enforcement entity


# Evidence patterns that weight toward each hypothesis. Each entry is
# (signal_name, weight). Heuristics, not rules - scoring sums whichever
# signals are actually present and confirmed by an earlier module.

_HYPOTHESIS_SIGNALS = {
    Hypothesis.PERSONAL_ADVERSARY: [
        ("single_named_individual",       3),
        ("no_corporate_structure",        2),
        ("personal_social_overlap",       2),
        ("single_jurisdiction",           1),
        ("low_infrastructure_investment", 1),
    ],
    Hypothesis.CORPORATE_ACTOR: [
        ("registered_corporation",        3),
        ("professional_infrastructure",   2),
        ("compliance_posture_present",    2),  # has SPF/DMARC, TOS, privacy policy
        ("public_facing_business",        2),
        ("single_jurisdiction",           1),
    ],
    Hypothesis.CRIMINAL_ENTERPRISE: [
        ("shell_company_chain_depth_gt_2", 3),
        ("multiple_jurisdictions",         2),
        ("identity_fragmentation_high",    3),
        ("offshore_leak_match",            3),
        ("ofac_match",                     4),
        ("burner_device_pattern",          2),
    ],
    Hypothesis.STATE_LEA: [
        ("government_tld",                    4),
        ("agency_naming_convention",          2),
        ("foia_adjacent_entity",              2),
        ("classified_infrastructure_pattern", 2),
    ],
}


def score_hypotheses(observed_signals):
    """
    observed_signals is a list of signal names that the investigator or
    earlier modules have actually confirmed are present - not guessed.
    Each signal should trace back to a specific finding (e.g.
    "ofac_match" only gets included if M3 actually returned an OFAC hit).

    Returns a score per hypothesis and the max possible score for each,
    so the output reads as "6 of 9 possible points toward X" rather than
    a bare number that looks more authoritative than it is.
    """
    observed = set(observed_signals)
    results = {}

    for hypothesis, signals in _HYPOTHESIS_SIGNALS.items():
        max_possible = sum(weight for _, weight in signals)
        achieved = sum(weight for name, weight in signals if name in observed)
        matched = [name for name, _ in signals if name in observed]

        results[hypothesis] = {
            "score": achieved,
            "max_possible": max_possible,
            "percentage": round(100 * achieved / max_possible, 1) if max_possible else 0,
            "matched_signals": matched,
        }

    ranked = sorted(results.items(), key=lambda x: x[1]["percentage"], reverse=True)

    return {
        "hypotheses": results,
        "ranked": [{"hypothesis": h, **data} for h, data in ranked],
        "leading_hypothesis": ranked[0][0] if ranked[0][1]["percentage"] > 0 else None,
        "note": (
            "These are weighted hypotheses based on observed evidence patterns, "
            "not conclusions. Multiple hypotheses can and often do score "
            "simultaneously - that's expected, not an error. This output is "
            "meant to focus further investigation, not to end it."
        ),
    }


# ─────────────────────────────────────────────────────────────────────
# ATTACK PROGRESSION TIMELINE
# ─────────────────────────────────────────────────────────────────────

_TIMELINE_PHASES = {
    "T-0": "Initial reconnaissance / first contact",
    "T-1": "Infrastructure setup / acquisition",
    "T-2": "Initial access / first compromise indicator",
    "T-3": "Persistence established",
    "T-4": "Data collection / lateral movement",
    "T-5": "Exfiltration / monetization / action on objective",
    "T-6": "Detection by investigator",
}


def build_timeline(events):
    """
    Takes a list of {"label", "timestamp", "phase"} events (phase is
    optional, one of T-0 through T-6, assigned by the investigator
    based on what each event represents) and orders them chronologically
    with phase labels attached.

    Produces a sequence, not a narrative. Does not claim the events are
    causally connected - only that this is the order they were observed.
    """
    parsed = []
    for e in events:
        try:
            ts = _parse_timestamp(e["timestamp"])
            parsed.append({
                "label": e["label"], "timestamp": ts, "phase": e.get("phase"),
                "phase_description": _TIMELINE_PHASES.get(e.get("phase")),
            })
        except (ValueError, TypeError, KeyError):
            continue

    parsed.sort(key=lambda x: x["timestamp"])

    return {
        "events": [
            {"label": p["label"], "timestamp": p["timestamp"].isoformat(),
             "phase": p["phase"], "phase_description": p["phase_description"]}
            for p in parsed
        ],
        "span_days": (parsed[-1]["timestamp"] - parsed[0]["timestamp"]).days if len(parsed) >= 2 else 0,
        "note": "Chronological order of observed events. Sequence does not imply causation.",
    }


# ─────────────────────────────────────────────────────────────────────
# MAIN MODULE CLASS
# ─────────────────────────────────────────────────────────────────────

class AttributionEngine:
    """
    Differentiates self-owned from subject-owned artifacts, scores
    relationship hypotheses, and builds an attack progression timeline.
    Every output is framed as investigative hypothesis, not legal
    conclusion - that framing is load-bearing, not decoration. A report
    that asserts certainty it doesn't have is worse than no report.
    """

    def __init__(self, journal=None):
        self.journal = journal or EvidenceJournal()

    def differentiate(self, artifacts, self_identifiers, subject_identifiers,
                       observed_signals=None, timeline_events=None):
        print(f"\n[CTF/M8] Self/subject differentiation & attribution hypotheses")

        classification = classify_all(artifacts, self_identifiers, subject_identifiers)
        self.journal.log(module="m8_attribution", query="ARTIFACT_CLASSIFICATION",
                          source="local-set-membership", response=classification["counts"])
        print(f"  [1/3] Artifact classification: {classification['counts']}")
        if classification.get("overlap_items"):
            print(f"        🚩 Overlap: {classification['overlap_items']}")

        result = {"classification": classification}

        if observed_signals:
            hyp = score_hypotheses(observed_signals)
            self.journal.log(
                module="m8_attribution", query="HYPOTHESIS_SCORING",
                source="local-weighted-scoring",
                response={h: d["percentage"] for h, d in hyp["hypotheses"].items()}
            )
            print(f"\n  [2/3] Relationship hypotheses:")
            for r in hyp["ranked"]:
                bar = "█" * int(r["percentage"] // 10) + "░" * (10 - int(r["percentage"] // 10))
                print(f"        {r['hypothesis']:<22} {r['percentage']:>5.1f}% [{bar}] ({r['score']}/{r['max_possible']})")
            result["hypotheses"] = hyp
        else:
            print(f"\n  [2/3] No signals provided - skipping hypothesis scoring")

        if timeline_events:
            timeline = build_timeline(timeline_events)
            self.journal.log(
                module="m8_attribution", query="TIMELINE_CONSTRUCTION",
                source="local-chronological-ordering",
                response={"event_count": len(timeline["events"]), "span_days": timeline["span_days"]}
            )
            print(f"\n  [3/3] Timeline: {len(timeline['events'])} events over {timeline['span_days']} days")
            for e in timeline["events"]:
                phase_str = f" [{e['phase']}]" if e["phase"] else ""
                print(f"        {e['timestamp'][:10]}{phase_str} {e['label']}")
            result["timeline"] = timeline
        else:
            print(f"\n  [3/3] No timeline events provided - skipping")

        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        result["disclaimer"] = (
            "This output organizes evidence into investigative hypotheses. "
            "It is not a legal conclusion and does not establish that any "
            "named person or entity committed any act. Verify findings "
            "through appropriate legal process before acting on them."
        )

        return result


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 8 Attribution Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        engine = AttributionEngine(journal=journal)

        # Synthetic identifiers - .example TLD and 192.0.2.x are IANA
        # reserved-for-documentation ranges (RFC 2606 / RFC 5737), used
        # here as test fixtures, not real third-party identifiers.
        self_ids    = ["investigator@personalmail.example", "+15125550100", "356938035643809"]
        subject_ids = ["admin@shellcorp.example", "ssiloc.example", "192.0.2.88"]

        artifacts = [
            "investigator@personalmail.example",  # self
            "admin@shellcorp.example",             # subject
            "ssiloc.example",                      # subject
            "192.0.2.88",                          # subject
            "+15125550100",                        # self
            "unrelated-domain.example",             # neutral
        ]

        observed_signals = [
            "shell_company_chain_depth_gt_2",
            "multiple_jurisdictions",
            "identity_fragmentation_high",
        ]

        timeline_events = [
            {"label": "Subject domain first appears in network logs", "timestamp": "2026-01-08T14:00:00Z", "phase": "T-1"},
            {"label": "First compromise indicator observed", "timestamp": "2026-01-10T09:00:00Z", "phase": "T-2"},
            {"label": "Detected via SMS loop-back test", "timestamp": "2026-02-01T11:00:00Z", "phase": "T-6"},
        ]

        engine.differentiate(
            artifacts, self_ids, subject_ids,
            observed_signals=observed_signals,
            timeline_events=timeline_events,
        )

        v = journal.verify()
        print(f"\nEvidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 8 self-test complete.")
        print("=" * 60)
