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
    "ip": str,           # CIDR representation of the node
    "scope_status": str, # one of the above values
    "rule_ids": list,    # policy_ids of rules that produced this classification
    "label": str,        # human-readable label (from interface names etc.)
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


def _parse_cidr(addr: str) -> ipaddress.IPv4Network | None:
    """Try to parse addr as an IPv4Network. Returns None for unresolvable names."""
    if not addr or addr.startswith("wildcard:"):
        return None
    if addr.startswith("fqdn:"):
        # If combined fqdn|ip format, extract the IP portion
        if "|" in addr:
            addr = addr.split("|", 1)[1]
        else:
            return None
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
    Build an adjacency graph: node → list of {target, rule_id, services}.
    Nodes are CIDR strings. 'all' / '0.0.0.0/0' is stored as "0.0.0.0/0".
    """
    graph: dict[str, list[dict]] = defaultdict(list)

    for rule in rules:
        if rule.get("action") != "permit":
            continue
        rule_id = rule.get("policy_id", "?")
        for src in rule.get("src_addrs", []):
            for dst in rule.get("dst_addrs", []):
                graph[src].append({
                    "target": dst,
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
) -> list[dict]:
    """
    Classify network nodes based on reachability from CDE seeds.

    Args:
        rules:           normalized rule dicts from parsers
        cde_seeds:       list of CIDR strings the user identified as CDE
        interface_table: optional {intf_name: cidr} from parser for labeling

    Returns:
        list of scope node dicts
    """
    if interface_table is None:
        interface_table = {}

    # Reverse map: CIDR → interface name
    cidr_to_intf: dict[str, str] = {v: k for k, v in interface_table.items()}

    # Collect all unique CIDRs mentioned in rules
    all_cidrs: set[str] = set()
    for rule in rules:
        for addr in rule.get("src_addrs", []) + rule.get("dst_addrs", []):
            if _parse_cidr(addr) is not None:
                all_cidrs.add(addr)
    # Add seed CIDRs
    for seed in cde_seeds:
        if _parse_cidr(seed) is not None:
            all_cidrs.add(seed)

    # Parse all cidrs once
    cidr_nets: dict[str, ipaddress.IPv4Network] = {}
    for c in all_cidrs:
        n = _parse_cidr(c)
        if n is not None:
            cidr_nets[c] = n

    # Build forward + reverse adjacency
    fwd_graph = _build_graph(rules)
    rev_graph: dict[str, list[dict]] = defaultdict(list)
    for src, edges in fwd_graph.items():
        for edge in edges:
            rev_graph[edge["target"]].append({
                "target": src,
                "rule_id": edge["rule_id"],
                "services": edge["services"],
            })

    # Helper: resolve all CIDRs that a query CIDR overlaps with
    def overlapping_nodes(query: str) -> list[str]:
        q_net = _parse_cidr(query)
        if q_net is None:
            return [query]
        return [c for c, n in cidr_nets.items() if _networks_overlap(q_net, n)]

    # BFS helpers
    def reachable_from(start_nodes: set[str], graph: dict[str, list[dict]]) -> dict[str, list[str]]:
        """BFS returning {node: list of rule_ids that connected it}."""
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
    seed_set = set(cde_seeds)

    # BFS forward (what can reach FROM CDE or be reached FROM CDE)
    fwd_reachable = reachable_from(seed_set, fwd_graph)
    rev_reachable = reachable_from(seed_set, rev_graph)

    # Union of forward + reverse = "connected" zone
    connected_nodes: set[str] = set(fwd_reachable) | set(rev_reachable)

    # Security-providing: systems that provide services to CDE on security ports
    security_providing: set[str] = set()
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        dst_addrs = rule.get("dst_addrs", [])
        # If destination overlaps with a CDE seed
        dst_is_cde = any(
            any(_networks_overlap(cidr_nets[s], cidr_nets[d])
                for s in cde_seeds if s in cidr_nets and d in cidr_nets)
            for d in dst_addrs
        )
        if not dst_is_cde:
            continue
        # Check if services are security-related
        for svc in rule.get("services", []):
            port = _extract_port(svc)
            if port in _SECURITY_PORTS:
                for src in rule.get("src_addrs", []):
                    security_providing.add(src)
                break

    # Build result list
    nodes_to_classify = all_cidrs | connected_nodes

    result: list[dict] = []
    classified: set[str] = set()

    for cidr in sorted(nodes_to_classify):
        if cidr in classified:
            continue
        classified.add(cidr)

        net = cidr_nets.get(cidr)
        label = cidr_to_intf.get(cidr, "")

        # Skip pure internet nodes unless they're in scope
        if net and _is_internet(net) and cidr not in seed_set and cidr not in connected_nodes:
            continue

        if cidr in seed_set:
            scope_status = "cde"
            rule_ids: list[str] = []
        elif cidr in security_providing and cidr not in seed_set:
            scope_status = "security_providing"
            rule_ids = [str(r) for r in fwd_reachable.get(cidr, [])]
        elif cidr in connected_nodes:
            scope_status = "connected"
            rule_ids = [str(r) for r in (fwd_reachable.get(cidr, []) + rev_reachable.get(cidr, []))]
        else:
            scope_status = "out_of_scope"
            rule_ids = []

        result.append({
            "ip": cidr,
            "scope_status": scope_status,
            "rule_ids": rule_ids,
            "label": label,
        })

    return result
