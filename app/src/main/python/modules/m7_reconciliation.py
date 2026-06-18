#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 7 - Reconciliation & Anomaly Classification

One job: Take everything the investigation has found and check whether
it actually holds together. Four coherence checks, each producing a
score, combined into one overall confidence rating.

Pure analysis on data already collected - no network calls. Math and
logic only: haversine distance for geography, timestamp ordering for
chronology, set counting for identity fragmentation.

The output is a confidence score and a classification label, never a
verdict. CONFIRMED still means "the evidence is internally consistent
and well-supported," not "this is legally proven." That distinction
matters for anything headed toward a report.
"""

import math
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
    """Parse a timestamp string, with or without dateutil."""
    if DATEUTIL_AVAILABLE:
        return date_parser.parse(ts)
    # Fallback: handle the common ISO 8601 with Z suffix
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ─────────────────────────────────────────────────────────────────────
# CLASSIFICATION LABELS
# ─────────────────────────────────────────────────────────────────────

class Classification:
    CONFIRMED    = "CONFIRMED"     # 8.0-10.0: internally consistent, well-corroborated
    PROBABLE     = "PROBABLE"      # 6.0-7.9:  consistent, some gaps
    POSSIBLE     = "POSSIBLE"      # 3.0-5.9:  plausible, significant gaps
    INSUFFICIENT = "INSUFFICIENT"  # 0.0-2.9:  not enough to support a conclusion


# ─────────────────────────────────────────────────────────────────────
# GEOGRAPHIC COHERENCE
# ─────────────────────────────────────────────────────────────────────

def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points in kilometers. Pure math."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def geographic_coherence(locations):
    """
    Takes a list of {"label", "lat", "lon"} points found across the
    investigation (registrant address, IP geolocation, FCC equipment
    region) and checks how tightly they cluster.

    <100km scatter:     LEGITIMATE - one operator, one place
    100-2000km scatter: INTENTIONAL_OR_VPN - consistent with VPN/proxy
                         or a business with multiple offices
    >2000km scatter:    ANOMALOUS - consistent with spoofed location
                         data, compromised infrastructure, or a
                         genuinely distributed operation
    """
    valid = [l for l in locations if l.get("lat") is not None and l.get("lon") is not None]

    if len(valid) < 2:
        return {
            "checked": len(valid) >= 1,
            "max_distance_km": 0,
            "classification": "INSUFFICIENT_DATA",
            "points": len(valid),
        }

    distances = []
    for i in range(len(valid)):
        for j in range(i + 1, len(valid)):
            d = haversine_km(valid[i]["lat"], valid[i]["lon"], valid[j]["lat"], valid[j]["lon"])
            distances.append({"from": valid[i]["label"], "to": valid[j]["label"], "distance_km": round(d, 1)})

    max_dist = max(d["distance_km"] for d in distances)

    if max_dist < 100:
        classification = "LEGITIMATE"
    elif max_dist < 2000:
        classification = "INTENTIONAL_OR_VPN"
    else:
        classification = "ANOMALOUS"

    return {
        "checked": True,
        "points": len(valid),
        "max_distance_km": round(max_dist, 1),
        "pairwise_distances": distances,
        "classification": classification,
    }


# ─────────────────────────────────────────────────────────────────────
# TEMPORAL COHERENCE
# ─────────────────────────────────────────────────────────────────────

def temporal_coherence(events):
    """
    Takes a list of {"label", "timestamp"} events and checks for
    ordering violations - things that happened in an impossible
    sequence (a certificate issued before the domain was registered).

    Each violation is a real signal: either the records were backdated,
    or two different "facts" are actually about two different entities
    that got conflated.
    """
    parsed = []
    errors = []
    for e in events:
        try:
            ts = _parse_timestamp(e["timestamp"])
            parsed.append({"label": e["label"], "timestamp": ts})
        except (ValueError, TypeError, KeyError) as err:
            errors.append({"event": e.get("label", "unknown"), "error": str(err)})

    parsed.sort(key=lambda x: x["timestamp"])

    violations = []
    expected_order = ["registered", "incorporated", "founded", "created"]
    cert_order = ["certificate", "cert_issued"]

    reg_events = [p for p in parsed if any(k in p["label"].lower() for k in expected_order)]
    cert_events = [p for p in parsed if any(k in p["label"].lower() for k in cert_order)]

    for reg in reg_events:
        for cert in cert_events:
            if cert["timestamp"] < reg["timestamp"]:
                violations.append({
                    "type": "CERT_BEFORE_REGISTRATION",
                    "registration": reg["label"],
                    "registration_date": reg["timestamp"].isoformat(),
                    "certificate": cert["label"],
                    "certificate_date": cert["timestamp"].isoformat(),
                    "note": "Certificate issued before registration date - backdated records or conflated entities",
                })

    return {
        "checked": len(parsed) >= 2,
        "events_parsed": len(parsed),
        "parse_errors": errors,
        "timeline": [{"label": p["label"], "timestamp": p["timestamp"].isoformat()} for p in parsed],
        "violations": violations,
        "classification": "ANOMALOUS" if violations else ("LEGITIMATE" if parsed else "INSUFFICIENT_DATA"),
    }


# ─────────────────────────────────────────────────────────────────────
# ENTITY IDENTITY COHERENCE
# ─────────────────────────────────────────────────────────────────────

def identity_coherence(identities):
    """
    Counts distinct named entities tied to one investigation thread.

    1 identity:     LEGITIMATE - one person/company, consistent picture
    2-3 identities: INTENTIONAL_FRAGMENTATION - consistent with shell
                    company structuring, not automatically fraud (lots
                    of legitimate businesses use holding companies),
                    but worth flagging
    >3 identities:  ANOMALOUS - consistent with a fraud ring or
                    deliberate attribution obstruction
    """
    distinct = set(i.strip().lower() for i in identities if i)
    count = len(distinct)

    if count <= 1:
        classification = "LEGITIMATE"
    elif count <= 3:
        classification = "INTENTIONAL_FRAGMENTATION"
    else:
        classification = "ANOMALOUS"

    return {
        "checked": count > 0,
        "distinct_identities": count,
        "identities": list(distinct),
        "classification": classification,
    }


# ─────────────────────────────────────────────────────────────────────
# INFRASTRUCTURE TOPOLOGY COHERENCE
# ─────────────────────────────────────────────────────────────────────

def infrastructure_topology_coherence(infra_types):
    """
    Checks whether the mix of infrastructure types makes sense together.

    All datacenter:               CONSISTENT - automated/professional setup
    All residential:               CONSISTENT - individual operator
    Mixed datacenter+residential:  WORTH_FLAGGING - common pattern when a
                                    compromised home device is used as a
                                    relay alongside rented infrastructure
    Includes VPN/proxy:            OBFUSCATION_PRESENT - doesn't prove
                                    malice alone, but means geographic
                                    and ownership signals from that hop
                                    should be weighted down
    """
    types = [t for t in infra_types if t]
    type_set = set(types)

    obfuscation = "vpn" in type_set or "proxy" in type_set
    mixed = len(type_set - {"vpn", "proxy"}) > 1

    if obfuscation:
        classification = "OBFUSCATION_PRESENT"
    elif mixed:
        classification = "WORTH_FLAGGING"
    elif type_set:
        classification = "CONSISTENT"
    else:
        classification = "INSUFFICIENT_DATA"

    return {
        "checked": len(types) > 0,
        "types_seen": list(type_set),
        "type_counts": {t: types.count(t) for t in type_set},
        "classification": classification,
    }


# ─────────────────────────────────────────────────────────────────────
# OVERALL CONFIDENCE SCORING
# ─────────────────────────────────────────────────────────────────────

_SCORE_TABLE = {
    "geographic": {"LEGITIMATE": 2.5, "INTENTIONAL_OR_VPN": 1.0, "ANOMALOUS": 0.0, "INSUFFICIENT_DATA": 1.0},
    "temporal":   {"LEGITIMATE": 2.5, "ANOMALOUS": 0.0, "INSUFFICIENT_DATA": 1.0},
    "identity":   {"LEGITIMATE": 2.5, "INTENTIONAL_FRAGMENTATION": 1.5, "ANOMALOUS": 0.5, "INSUFFICIENT_DATA": 1.0},
    "topology":   {"CONSISTENT": 2.5, "WORTH_FLAGGING": 1.5, "OBFUSCATION_PRESENT": 1.0, "INSUFFICIENT_DATA": 1.0},
}


def compute_confidence(geo_result, temporal_result, identity_result, topology_result):
    """Combine all four coherence checks into one 0-10 confidence score."""
    score = 0.0
    score += _SCORE_TABLE["geographic"].get(geo_result["classification"], 1.0)
    score += _SCORE_TABLE["temporal"].get(temporal_result["classification"], 1.0)
    score += _SCORE_TABLE["identity"].get(identity_result["classification"], 1.0)
    score += _SCORE_TABLE["topology"].get(topology_result["classification"], 1.0)

    if score >= 8.0:
        label = Classification.CONFIRMED
    elif score >= 6.0:
        label = Classification.PROBABLE
    elif score >= 3.0:
        label = Classification.POSSIBLE
    else:
        label = Classification.INSUFFICIENT

    return {
        "score": round(score, 1),
        "max_score": 10.0,
        "classification": label,
        "note": (
            f"{label} reflects internal consistency of the evidence collected, "
            "not legal proof. Use alongside the underlying evidence chain, "
            "not as a substitute for it."
        ),
    }


# ─────────────────────────────────────────────────────────────────────
# MAIN MODULE CLASS
# ─────────────────────────────────────────────────────────────────────

class Reconciliation:
    """Runs all four coherence checks and produces an overall confidence score."""

    def __init__(self, journal=None):
        self.journal = journal or EvidenceJournal()

    def reconcile(self, locations=None, events=None, identities=None, infra_types=None):
        """
        Run all four checks. Each argument is optional - pass what you
        have. Missing checks default to INSUFFICIENT_DATA rather than
        failing the whole reconciliation.
        """
        print(f"\n[CTF/M7] Reconciliation & anomaly classification")

        geo = geographic_coherence(locations or [])
        self.journal.log(module="m7_reconciliation", query="GEOGRAPHIC_COHERENCE",
                          source="local-haversine-calculation", response=geo)
        suffix = f" (max spread: {geo['max_distance_km']} km)" if geo.get("max_distance_km") else ""
        print(f"  [1/4] Geographic coherence: {geo['classification']}{suffix}")

        temporal = temporal_coherence(events or [])
        self.journal.log(module="m7_reconciliation", query="TEMPORAL_COHERENCE",
                          source="local-timestamp-ordering", response=temporal)
        print(f"  [2/4] Temporal coherence: {temporal['classification']}")
        for v in temporal.get("violations", []):
            print(f"        🚩 {v['type']}: {v['note']}")

        identity = identity_coherence(identities or [])
        self.journal.log(module="m7_reconciliation", query="IDENTITY_COHERENCE",
                          source="local-set-counting", response=identity)
        print(f"  [3/4] Identity coherence: {identity['classification']} ({identity['distinct_identities']} distinct identities)")

        topology = infrastructure_topology_coherence(infra_types or [])
        self.journal.log(module="m7_reconciliation", query="TOPOLOGY_COHERENCE",
                          source="local-classification", response=topology)
        print(f"  [4/4] Infrastructure topology: {topology['classification']}")

        confidence = compute_confidence(geo, temporal, identity, topology)
        self.journal.log(module="m7_reconciliation", query="OVERALL_CONFIDENCE",
                          source="local-scoring-engine", response=confidence)

        print(f"\n  Overall: {confidence['classification']} ({confidence['score']}/10)")

        return {
            "geographic": geo, "temporal": temporal, "identity": identity, "topology": topology,
            "confidence": confidence, "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 7 Reconciliation Self-Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        recon = Reconciliation(journal=journal)

        print("\nTest 1: Coherent case (should score high)")
        recon.reconcile(
            locations=[
                {"label": "registrant_address", "lat": 30.2672, "lon": -97.7431},  # Austin
                {"label": "ip_geolocation", "lat": 30.3000, "lon": -97.7000},       # Also Austin
            ],
            events=[
                {"label": "domain_registered", "timestamp": "2023-01-15T00:00:00Z"},
                {"label": "certificate_issued", "timestamp": "2023-01-16T00:00:00Z"},
            ],
            identities=["John Smith"],
            infra_types=["residential"],
        )

        print("\n" + "─" * 40)
        print("Test 2: Anomalous case (should score low, catch violations)")
        recon.reconcile(
            locations=[
                {"label": "registrant_address", "lat": 30.2672, "lon": -97.7431},  # Austin
                {"label": "ip_geolocation", "lat": 55.7558, "lon": 37.6173},       # Moscow
            ],
            events=[
                {"label": "domain_registered", "timestamp": "2023-06-01T00:00:00Z"},
                {"label": "certificate_issued", "timestamp": "2023-01-01T00:00:00Z"},  # before registration!
            ],
            identities=["Shell Corp A", "Shell Corp B", "Shell Corp C", "Shell Corp D"],
            infra_types=["datacenter", "residential", "vpn"],
        )

        v = journal.verify()
        print(f"\nEvidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 7 self-test complete.")
        print("=" * 60)
