"""
Scope propagation engine.

Given a list of normalized firewall rules and a set of CDE seed IPs/CIDRs,
classify every discovered network node as:
  - cde              (user-declared or AI-confirmed as storing/processing/transmitting CHD)
  - connected        (bidirectional permitted access to/from CDE)
  - security_providing (provides auth/DNS/NTP/logging services to CDE)
  - out_of_scope     (no permitted path to CDE)
  - unknown          (discovered node, not yet classified)

Returns a list of scope node dicts:
  {
    "ip": str,           # normalized CIDR, or "fqdn:name" for FQDN-only entries
    "scope_status": str, # one of the above values
    "rule_ids": list,    # policy_ids of rules that produced this classification
    "label": str,        # interface name label (from interface_table)
    "name": str,         # address object name or FQDN hostname label
  }
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECURITY_PORTS = {
    "389", "636",    # LDAP/LDAPS
    "88",            # Kerberos
    "514",           # Syslog
    "53",            # DNS
    "123",           # NTP
    "161", "162",    # SNMP
    "443", "8443",   # could be security console
    "5601",          # Kibana/SIEM
    "9200",          # Elasticsearch
}


def _normalize_addr(addr: str) -> tuple[str | None, str]:
    """
    Normalize a raw address string to (canonical_key, fqdn_label).

    canonical_key:
    - str(IPv4Network) for valid IP/CIDR inputs
    - "fqdn:hostname" for bare FQDN inputs (no resolved IP)
    - str(IPv4Network) for "fqdn:hostname|ip" combined inputs (IP is canonical)
    - None for wildcards, empty strings, or unresolvable garbage

    fqdn_label: the FQDN hostname for "fqdn:hostname|ip" entries; "" otherwise.
    """
    if not addr or addr.startswith("wildcard:"):
        return None, ""
    if addr.startswith("fqdn:"):
        if "|" in addr:
            fqdn_part, ip_part = addr.split("|", 1)
            fqdn_label = fqdn_part[5:]  # strip "fqdn:"
            try:
                net = ipaddress.ip_network(ip_part, strict=False)
                return str(net), fqdn_label
            except ValueError:
                return None, ""
        else:
            fqdn_label = addr[5:]
            return addr, fqdn_label  # bare fqdn kept as canonical key
    try:
        net = ipaddress.ip_network(addr, strict=False)
        return str(net), ""
    except ValueError:
        return None, ""  # unresolvable garbage — filter out


def _parse_cidr(addr: str) -> ipaddress.IPv4Network | None:
    """Parse a CIDR/IP string to IPv4Network (used for overlap comparisons)."""
    try:
        return ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return None


def _is_internet(net: ipaddress.IPv4Network | None) -> bool:
    if net is None:
        return False
    return net.prefixlen == 0 or (
        not net.is_private
        and not net.is_loopback
        and not net.is_link_local
    )


def _networks_overlap(
    a: ipaddress.IPv4Network,
    b: ipaddress.IPv4Network,
) -> bool:
    return a.overlaps(b)


def _extract_port(service: str) -> str | None:
    """Extract port number from 'proto/port' string."""
    parts = service.split("/")
    if len(parts) == 2:
        return parts[1].split("-")[0]  # handle ranges like 8080-8090
    return None


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def _build_graph(rules: list[dict]) -> dict[str, list[dict]]:
    """
    Build an adjacency graph using normalized address keys.
    Filters out wildcards, unresolvable names, and empty addresses.
    Nodes are normalized CIDR strings or "fqdn:name" for bare FQDNs.
    """
    graph: dict[str, list[dict]] = defaultdict(list)

    for rule in rules:
        if rule.get("action") != "permit":
            continue
        rule_id = rule.get("policy_id", "?")
        for src_raw in rule.get("src_addrs", []):
            src_key, _ = _normalize_addr(src_raw)
            if src_key is None:
                continue
            for dst_raw in rule.get("dst_addrs", []):
                dst_key, _ = _normalize_addr(dst_raw)
                if dst_key is None:
                    continue
                graph[src_key].append({
                    "target": dst_key,
                    "rule_id": rule_id,
                    "services": rule.get("services", ["ALL"]),
                })

    return dict(graph)


# ---------------------------------------------------------------------------
# Scope classifier
# ---------------------------------------------------------------------------

def classify_scope(
    rules: list[dict],
    cde_seeds: list[str],
    interface_table: dict[str, str] | None = None,
    addr_label_map: dict[str, str] | None = None,
) -> list[dict]:
    """
    Classify network nodes based on reachability from CDE seeds.

    Args:
        rules:           normalized rule dicts from parsers
        cde_seeds:       list of CIDR strings the user identified as CDE
        interface_table: optional {intf_name: cidr} from parser for labeling
        addr_label_map:  optional {cidr: object_name} built by the parser

    Returns:
        list of scope node dicts
    """
    if interface_table is None:
        interface_table = {}
    if addr_label_map is None:
        addr_label_map = {}

    # Reverse map: CIDR → interface name
    cidr_to_intf: dict[str, str] = {v: k for k, v in interface_table.items()}

    # Collect all unique addresses mentioned in rules, normalized
    all_cidrs: set[str] = set()         # valid IP network strings only
    fqdn_nodes: dict[str, str] = {}     # fqdn_key → fqdn_label
    cidr_fqdn_labels: dict[str, str] = {}  # cidr → fqdn label (from fqdn|ip entries)

    for rule in rules:
        for addr_raw in rule.get("src_addrs", []) + rule.get("dst_addrs", []):
            key, label = _normalize_addr(addr_raw)
            if key is None:
                continue
            if key.startswith("fqdn:"):
                fqdn_nodes[key] = label
            else:
                all_cidrs.add(key)
                if label:
                    cidr_fqdn_labels.setdefault(key, label)

    # Normalize and add CDE seeds
    seed_set: set[str] = set()
    for seed in cde_seeds:
        key, _ = _normalize_addr(seed)
        if key is not None and not key.startswith("fqdn:"):
            all_cidrs.add(key)
            seed_set.add(key)

    # Parse all CIDR nodes to IPv4Network objects
    cidr_nets: dict[str, ipaddress.IPv4Network] = {}
    for c in all_cidrs:
        n = _parse_cidr(c)
        if n is not None:
            cidr_nets[c] = n

    # Build forward + reverse adjacency (graph uses normalized keys)
    fwd_graph = _build_graph(rules)
    rev_graph: dict[str, list[dict]] = defaultdict(list)
    for src, edges in fwd_graph.items():
        for edge in edges:
            rev_graph[edge["target"]].append({
                "target": src,
                "rule_id": edge["rule_id"],
                "services": edge["services"],
            })

    # Helper: find all CIDR nodes that overlap with query (or return FQDN key as-is)
    def overlapping_nodes(query: str) -> list[str]:
        q_net = _parse_cidr(query)
        if q_net is None:
            return [query]  # FQDN keys: look up directly in graph
        return [c for c, n in cidr_nets.items() if _networks_overlap(q_net, n)]

    # BFS returning {node: list_of_rule_ids}
    def reachable_from(start_nodes: set[str], graph: dict[str, list[dict]]) -> dict[str, list[str]]:
        visited: dict[str, list[str]] = {n: [] for n in start_nodes}
        queue: deque[str] = deque(start_nodes)
        while queue:
            current = queue.popleft()
            for candidate in overlapping_nodes(current):
                for edge in graph.get(candidate, []):
                    target = edge["target"]
                    if target not in visited:
                        visited[target] = edge["rule_id"] if isinstance(edge["rule_id"], list) else [str(edge["rule_id"])]
                        queue.append(target)
        return visited

    # Seed CDE nodes
    fwd_reachable = reachable_from(seed_set, fwd_graph)
    rev_reachable = reachable_from(seed_set, rev_graph)

    connected_nodes: set[str] = set(fwd_reachable) | set(rev_reachable)
    cidr_connected = {n for n in connected_nodes if not n.startswith("fqdn:")}
    fqdn_connected = {n for n in connected_nodes if n.startswith("fqdn:")}

    # Security-providing: systems that provide services to CDE on security ports
    security_providing: set[str] = set()
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        dst_normalized = []
        for d_raw in rule.get("dst_addrs", []):
            d_key, _ = _normalize_addr(d_raw)
            if d_key is not None and not d_key.startswith("fqdn:"):
                dst_normalized.append(d_key)

        dst_is_cde = any(
            any(_networks_overlap(cidr_nets[s], cidr_nets[d])
                for s in seed_set if s in cidr_nets and d in cidr_nets)
            for d in dst_normalized
        )
        if not dst_is_cde:
            continue
        for svc in rule.get("services", []):
            port = _extract_port(svc)
            if port in _SECURITY_PORTS:
                for src_raw in rule.get("src_addrs", []):
                    src_key, _ = _normalize_addr(src_raw)
                    if src_key is not None and not src_key.startswith("fqdn:"):
                        security_providing.add(src_key)
                break

    # Classify CIDR nodes
    nodes_to_classify = all_cidrs | cidr_connected

    result: list[dict] = []
    classified: set[str] = set()

    for cidr in sorted(nodes_to_classify):
        if cidr in classified:
            continue
        classified.add(cidr)

        net = cidr_nets.get(cidr)
        intf_label = cidr_to_intf.get(cidr, "")

        # Skip pure internet nodes unless they're in scope
        if net and _is_internet(net) and cidr not in seed_set and cidr not in cidr_connected:
            continue

        if cidr in seed_set:
            scope_status = "cde"
            rule_ids: list[str] = []
        elif cidr in security_providing and cidr not in seed_set:
            scope_status = "security_providing"
            rule_ids = [str(r) for r in fwd_reachable.get(cidr, [])]
        elif cidr in cidr_connected:
            scope_status = "connected"
            rule_ids = [str(r) for r in (fwd_reachable.get(cidr, []) + rev_reachable.get(cidr, []))]
        else:
            scope_status = "out_of_scope"
            rule_ids = []

        # Object name from parser label map, or FQDN label if this IP came from fqdn|ip entry
        obj_name = addr_label_map.get(cidr, "") or cidr_fqdn_labels.get(cidr, "")

        result.append({
            "ip": cidr,
            "scope_status": scope_status,
            "rule_ids": rule_ids,
            "label": intf_label,
            "name": obj_name,
        })

    # Classify FQDN-only nodes (no resolved IP)
    for fqdn_key in sorted(fqdn_nodes):
        fqdn_label = fqdn_nodes[fqdn_key]
        if fqdn_key in fqdn_connected:
            scope_status = "connected"
            rule_ids = [str(r) for r in (fwd_reachable.get(fqdn_key, []) + rev_reachable.get(fqdn_key, []))]
        else:
            scope_status = "unknown"
            rule_ids = []

        result.append({
            "ip": fqdn_key,
            "scope_status": scope_status,
            "rule_ids": rule_ids,
            "label": "",
            "name": fqdn_label,
        })

    return result
