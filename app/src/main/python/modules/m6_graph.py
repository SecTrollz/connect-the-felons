#!/usr/bin/env python3
"""
CONNECT THE FELONS
Module 6 - Association Graph

One job: Take everything every other module has found and represent it
as a graph. Nodes are entities (domains, IPs, emails, people, companies,
devices, ASNs, certificates). Edges are relationships between them, each
carrying a confidence score for how strong that link actually is.

Pure data organization - no network calls, no new data collection.
Everything here operates on findings other modules already logged to
the evidence journal. Built on NetworkX (free, local, no API).

Confidence scoring on edges matters because not every link is equally
solid. "This domain's WHOIS lists this email" is a 95% confidence direct
link. "This domain shares an ASN with that domain" is a 40% confidence
weak association - thousands of unrelated domains share datacenter ASNs.
Treating those the same would make the graph useless for attribution.
"""

import json
import os
import sys
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evidence_journal import EvidenceJournal


# ─────────────────────────────────────────────────────────────────────
# NODE TYPES
# ─────────────────────────────────────────────────────────────────────

class NodeType:
    DOMAIN      = "domain"
    IP          = "ip"
    EMAIL       = "email"
    PHONE       = "phone"
    DEVICE      = "device"
    PERSON      = "person"
    CORPORATION = "corporation"
    ASN         = "asn"
    CERTIFICATE = "certificate"
    NETWORK     = "network"


# ─────────────────────────────────────────────────────────────────────
# EDGE CONFIDENCE WEIGHTS
# ─────────────────────────────────────────────────────────────────────
# Default confidence by relationship type. Override per-edge when a
# module already has a more specific score for that exact finding.

CONFIDENCE_WEIGHTS = {
    "direct_ownership":        95,  # WHOIS registrant, OpenCorporates officer
    "resolves_to":             95,  # domain -> IP via DNS
    "shared_registrant_email": 85,  # two domains, same WHOIS email
    "officer_of":              85,  # person listed as company officer
    "git_commit_author":       80,  # email tied to GitHub commits
    "certificate_org":         75,  # two domains share a cert's O= field
    "certificate_san":         70,  # two domains share a cert's SAN list
    "reverse_dns":             65,  # IP -> hostname
    "ofac_match":              90,  # sanctions list hit
    "icij_offshore_match":     85,  # appears in leaked offshore documents
    "same_asn":                40,  # weak - shared datacenter, not ownership
    "same_tac_model":          35,  # weak - same phone model, common
    "same_oui_manufacturer":   30,  # weak - millions of devices share OUI
    "weak_association":        40,  # generic fallback
}


# ─────────────────────────────────────────────────────────────────────
# MAIN GRAPH CLASS
# ─────────────────────────────────────────────────────────────────────

class AssociationGraph:
    """
    Wraps a NetworkX directed graph. Every node is an entity discovered
    during the investigation. Every edge is a relationship with a
    confidence score and a record of which module/query produced it.
    """

    def __init__(self, journal=None):
        if not NETWORKX_AVAILABLE:
            raise ImportError("networkx required: pip install networkx --break-system-packages")
        self.journal = journal or EvidenceJournal()
        self.graph = nx.MultiDiGraph()

    # ─────────────────────────────────────────────────────────────
    # BUILDING THE GRAPH
    # ─────────────────────────────────────────────────────────────

    def add_node(self, node_id, node_type, **attributes):
        """
        Add or update a node. node_id is normalized (lowercased) so the
        same entity found by two different modules collapses into one
        node instead of two.
        """
        node_id = self._normalize(node_id)
        if self.graph.has_node(node_id):
            self.graph.nodes[node_id].update(attributes)
            if "type" not in self.graph.nodes[node_id] or not self.graph.nodes[node_id].get("type"):
                self.graph.nodes[node_id]["type"] = node_type
        else:
            self.graph.add_node(node_id, type=node_type, **attributes)
        return node_id

    def add_edge(self, from_id, to_id, relationship, confidence=None,
                 source_module=None, evidence_hash=None):
        """Add a relationship between two nodes."""
        from_id = self._normalize(from_id)
        to_id   = self._normalize(to_id)

        if confidence is None:
            confidence = CONFIDENCE_WEIGHTS.get(relationship, CONFIDENCE_WEIGHTS["weak_association"])

        self.graph.add_edge(
            from_id, to_id,
            relationship=relationship,
            confidence=confidence,
            source_module=source_module,
            evidence_hash=evidence_hash,
            added_at=datetime.now(timezone.utc).isoformat(),
        )

        self.journal.log(
            module="m6_graph",
            query=f"ADD_EDGE: {from_id} --[{relationship}]--> {to_id}",
            source="local-graph-engine",
            response={"confidence": confidence, "source_module": source_module}
        )

    def from_investigation_results(self, results):
        """
        Ingest the results dict produced by main.py's Investigation class
        and automatically build nodes/edges from it. Bridges "everything
        we found" to "the graph that shows how it connects."
        """
        for key, finding in results.items():
            if isinstance(finding, dict):
                self._ingest_finding(finding)
        return self.summary()

    def _ingest_finding(self, finding):
        """Route a single finding dict to the right node/edge extraction."""
        # Infrastructure findings (M1)
        if "ips" in finding and "domain" in finding:
            domain = finding["domain"]
            self.add_node(domain, NodeType.DOMAIN)
            for ip, ip_data in finding.get("ips", {}).items():
                self.add_node(ip, NodeType.IP, infra_type=ip_data.get("infrastructure_type"))
                self.add_edge(domain, ip, "resolves_to", source_module="m1")

                asn = ip_data.get("asn", {}).get("asn")
                if asn:
                    self.add_node(asn, NodeType.ASN)
                    self.add_edge(ip, asn, "same_asn", source_module="m1")

        # Email/DNS findings (M2)
        if "whois" in finding and "domain" in finding:
            domain = finding["domain"]
            self.add_node(domain, NodeType.DOMAIN)
            email = finding["whois"].get("registrant_email")
            if email:
                self.add_node(email, NodeType.EMAIL)
                self.add_edge(email, domain, "direct_ownership", source_module="m2")

            for related in finding.get("certificates", {}).get("related_domains", []):
                self.add_node(related, NodeType.DOMAIN)
                self.add_edge(domain, related, "certificate_san", source_module="m2")

        # Ownership chain findings (M3)
        if "chain" in finding and "query" in finding:
            self._ingest_ownership_chain(finding["chain"])

        # Reverse infra findings (M4)
        if "github_commits" in finding:
            email = finding.get("email")
            if email:
                self.add_node(email, NodeType.EMAIL)
                for username in finding["github_commits"].get("usernames_found", []):
                    self.add_node(username, NodeType.PERSON, platform="github")
                    self.add_edge(email, username, "git_commit_author", source_module="m4")
            for domain in finding.get("certificate_domains", {}).get("domains", []):
                self.add_node(domain, NodeType.DOMAIN)

        # Device findings (M5)
        if "mac" in finding:
            mac = finding["mac"]
            self.add_node(mac, NodeType.DEVICE, device_class="network_interface")
            mfr = finding.get("oui", {}).get("manufacturer")
            if mfr:
                self.graph.nodes[self._normalize(mac)]["manufacturer"] = mfr

    def _ingest_ownership_chain(self, node, parent_name=None):
        """Recursively walk M3's ownership chain dict into graph nodes."""
        name = node.get("name")
        if not name:
            return
        entity_type = node.get("entity_type", "UNKNOWN")
        node_type = NodeType.PERSON if entity_type == "NATURAL_PERSON" else NodeType.CORPORATION

        self.add_node(name, node_type, entity_type=entity_type)

        if parent_name:
            self.add_edge(name, parent_name, "officer_of", source_module="m3")

        if node.get("metadata", {}).get("ofac_matches"):
            self.graph.nodes[self._normalize(name)]["ofac_flag"] = True

        for owner in node.get("owners", []):
            self._ingest_ownership_chain(owner, parent_name=name)

    # ─────────────────────────────────────────────────────────────
    # QUERYING THE GRAPH
    # ─────────────────────────────────────────────────────────────

    def expand(self, node_id, hops=1):
        """Get the subgraph within N hops of a node."""
        node_id = self._normalize(node_id)
        if node_id not in self.graph:
            return {"error": f"Node not found: {node_id}"}

        nodes_in_range = {node_id}
        frontier = {node_id}
        for _ in range(hops):
            next_frontier = set()
            for n in frontier:
                next_frontier.update(self.graph.successors(n))
                next_frontier.update(self.graph.predecessors(n))
            nodes_in_range.update(next_frontier)
            frontier = next_frontier

        subgraph = self.graph.subgraph(nodes_in_range)
        return self._graph_to_dict(subgraph)

    def find_clusters(self):
        """
        Find connected components - groups of entities that link to
        each other but not to other groups. Structural separation before
        M8 does semantic victim/subject classification.
        """
        undirected = self.graph.to_undirected()
        clusters = list(nx.connected_components(undirected))
        clusters.sort(key=len, reverse=True)

        return [
            {
                "cluster_id": i,
                "size": len(cluster),
                "nodes": list(cluster),
                "node_types": self._type_breakdown(cluster),
            }
            for i, cluster in enumerate(clusters)
        ]

    def shortest_path(self, node_a, node_b):
        """Find the shortest connection path between two entities."""
        a = self._normalize(node_a)
        b = self._normalize(node_b)
        undirected = self.graph.to_undirected()
        try:
            path = nx.shortest_path(undirected, a, b)
            edges = []
            for i in range(len(path) - 1):
                edge_data = self.graph.get_edge_data(path[i], path[i+1]) or \
                            self.graph.get_edge_data(path[i+1], path[i])
                if edge_data:
                    first_edge = list(edge_data.values())[0]
                    edges.append(first_edge.get("relationship"))
            return {"path": path, "relationships": edges, "hops": len(path) - 1}
        except nx.NetworkXNoPath:
            return {"path": None, "error": "No path exists between these nodes"}
        except nx.NodeNotFound as e:
            return {"path": None, "error": str(e)}

    def high_confidence_subgraph(self, min_confidence=70):
        """
        Return only edges above a confidence threshold. Cuts out weak
        associations (shared ASN, shared OUI) when you want only the
        links solid enough to act on.
        """
        strong_edges = [
            (u, v, k) for u, v, k, d in self.graph.edges(keys=True, data=True)
            if d.get("confidence", 0) >= min_confidence
        ]
        subgraph = self.graph.edge_subgraph(strong_edges) if strong_edges else self.graph.edge_subgraph([])
        return self._graph_to_dict(subgraph)

    # ─────────────────────────────────────────────────────────────
    # EXPORT
    # ─────────────────────────────────────────────────────────────

    def to_d3_json(self):
        """D3.js force-directed graph format."""
        nodes = [{"id": n, **d} for n, d in self.graph.nodes(data=True)]
        links = [
            {"source": u, "target": v, "relationship": d.get("relationship"), "confidence": d.get("confidence")}
            for u, v, d in self.graph.edges(data=True)
        ]
        return {"nodes": nodes, "links": links}

    def export(self, output_path=None):
        """Export full graph to JSON file."""
        data = {
            "investigation_id": self.journal.investigation_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "summary": self.summary(),
            "graph": self.to_d3_json(),
        }
        if output_path is None:
            report_dir = Path("investigations/graphs")
            report_dir.mkdir(parents=True, exist_ok=True)
            output_path = report_dir / f"{self.journal.investigation_id}_graph.json"

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return str(output_path)

    def summary(self):
        """Plain summary of graph size and composition."""
        type_counts = defaultdict(int)
        for _, d in self.graph.nodes(data=True):
            type_counts[d.get("type", "unknown")] += 1

        rel_counts = defaultdict(int)
        for _, _, d in self.graph.edges(data=True):
            rel_counts[d.get("relationship", "unknown")] += 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": dict(type_counts),
            "relationship_types": dict(rel_counts),
            "clusters": nx.number_connected_components(self.graph.to_undirected()),
        }

    # ─────────────────────────────────────────────────────────────
    # INTERNAL HELPERS
    # ─────────────────────────────────────────────────────────────

    def _normalize(self, node_id):
        return str(node_id).strip().lower()

    def _type_breakdown(self, node_ids):
        counts = defaultdict(int)
        for n in node_ids:
            counts[self.graph.nodes[n].get("type", "unknown")] += 1
        return dict(counts)

    def _graph_to_dict(self, g):
        return {
            "nodes": [{"id": n, **d} for n, d in g.nodes(data=True)],
            "edges": [{"from": u, "to": v, **d} for u, v, d in g.edges(data=True)],
        }


# ─────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("CONNECT THE FELONS - Module 6 Association Graph Self-Test")
    print("=" * 60)

    if not NETWORKX_AVAILABLE:
        print("\nERROR: networkx not installed. Run: pip install networkx --break-system-packages")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        journal = EvidenceJournal(base_dir=tmpdir)
        g = AssociationGraph(journal=journal)

        print("\nBuilding graph from synthetic investigation findings...")

        synthetic_results = {
            "infra:ssiloc.com": {
                "domain": "ssiloc.com",
                "ips": {"192.0.2.88": {"infrastructure_type": "datacenter", "asn": {"asn": "AS13335"}}},
            },
            "email_dns:ssiloc.com": {
                "domain": "ssiloc.com",
                "whois": {"registrant_email": "admin@shellcorp.example"},
                "certificates": {"related_domains": ["mirror-ssiloc.example"]},
            },
            "ownership:ShellCorp LLC": {
                "query": "ShellCorp LLC",
                "chain": {
                    "name": "ShellCorp LLC", "entity_type": "PRIVATE_COMPANY", "metadata": {},
                    "owners": [{
                        "name": "John Doe", "entity_type": "NATURAL_PERSON",
                        "metadata": {"role": "Director"}, "owners": [],
                    }],
                },
            },
        }

        g.from_investigation_results(synthetic_results)

        print("\nGraph summary:")
        s = g.summary()
        print(f"  Nodes: {s['total_nodes']}")
        print(f"  Edges: {s['total_edges']}")
        print(f"  Node types: {s['node_types']}")
        print(f"  Clusters: {s['clusters']}")

        print("\nExpanding from ssiloc.com (2 hops)...")
        expansion = g.expand("ssiloc.com", hops=2)
        print(f"  Nodes in range: {[n['id'] for n in expansion['nodes']]}")

        print("\nShortest path: ssiloc.com -> admin@shellcorp.example (should be connected)")
        path = g.shortest_path("ssiloc.com", "admin@shellcorp.example")
        if path.get("path"):
            print(f"  Path: {' -> '.join(path['path'])}")
            print(f"  Via: {path['relationships']}")
        else:
            print(f"  {path.get('error')}")

        print("\nShortest path: ssiloc.com -> John Doe (should NOT be connected)")
        print("  (No edge ever linked the email's domain to the company by name -")
        print("   the graph doesn't guess relationships from name similarity,")
        print("   only from evidence other modules actually confirmed)")
        path2 = g.shortest_path("ssiloc.com", "John Doe")
        if path2.get("path"):
            print(f"  Path: {' -> '.join(path2['path'])}")
        else:
            print(f"  Correctly reports no path: {path2.get('error')}")

        print("\nHigh-confidence subgraph (>=70):")
        hc = g.high_confidence_subgraph(min_confidence=70)
        print(f"  Nodes: {len(hc['nodes'])}, Edges: {len(hc['edges'])}")

        print("\nClusters:")
        for c in g.find_clusters():
            print(f"  Cluster {c['cluster_id']}: {c['size']} nodes - {c['node_types']}")

        v = journal.verify()
        print(f"\nEvidence chain: {v['entries_verified']} entries, valid={v['valid']}")

        print("\n" + "=" * 60)
        print("Module 6 self-test complete.")
        print("=" * 60)
