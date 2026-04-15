"""
PCI DSS v4.0 Gap Analysis Engine (Phase 1 — static checks).

Performs 5 core gap checks covering Requirement 1.2–1.5 and generates
static clarifying questions based on rule patterns.

Gap finding dict:
  {
    "id": str,
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "requirement": str,        # e.g. "PCI DSS v4.0 Req 1.3.2"
    "title": str,
    "description": str,
    "affected_rules": list[str],
    "remediation": str,
  }

Question dict:
  {
    "id": str,
    "category": str,           # "cde_id" | "ambiguity" | "segmentation" | "missing_rule"
    "text": str,
    "rule_id": str | None,
    "context": dict,           # extra data to render in UI
  }
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_net(addr: str) -> ipaddress.IPv4Network | None:
    if not addr or addr.startswith("fqdn:") or addr.startswith("wildcard:"):
        return None
    try:
        return ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return None


def _is_any(addr: str) -> bool:
    """True if addr represents 'all traffic' (any/0.0.0.0/0)."""
    if addr.lower() in ("all", "any", "0.0.0.0/0"):
        return True
    net = _parse_net(addr)
    return net is not None and net.prefixlen == 0


def _is_internet(addr: str) -> bool:
    net = _parse_net(addr)
    if net is None:
        return _is_any(addr)
    return net.prefixlen == 0 or (
        not net.is_private and not net.is_loopback and not net.is_link_local
    )


def _is_private(addr: str) -> bool:
    net = _parse_net(addr)
    if net is None:
        return False
    return net.is_private


def _overlaps_any_cde(addrs: list[str], cde_seeds: list[str]) -> bool:
    for a in addrs:
        a_net = _parse_net(a)
        if a_net is None:
            continue
        for seed in cde_seeds:
            s_net = _parse_net(seed)
            if s_net and a_net.overlaps(s_net):
                return True
    return False


def _extract_port(svc: str) -> str | None:
    parts = svc.split("/")
    return parts[1].split("-")[0] if len(parts) == 2 else None


_CARD_PROCESSING_PORTS = {"443", "8443", "4430", "8080", "8444", "9443"}
_KNOWN_PAYMENT_RANGES = [
    # Visa / MC / AMEX / PayPal (representative public ranges — not exhaustive)
    "208.43.0.0/16",
    "198.241.130.0/23",
    "64.4.248.0/21",
    "66.211.160.0/20",
]


# ---------------------------------------------------------------------------
# Gap checks
# ---------------------------------------------------------------------------

def _check_deny_all(rules: list[dict]) -> list[dict]:
    """Req 1.3.2 — Deny-all default at end of policy list."""
    findings = []
    has_deny_all = any(
        rule.get("action") == "deny"
        and all(_is_any(a) for a in rule.get("src_addrs", []))
        and all(_is_any(a) for a in rule.get("dst_addrs", []))
        for rule in rules
    )
    if not has_deny_all:
        findings.append({
            "id": "GAP-DENY-ALL",
            "severity": "high",
            "requirement": "PCI DSS v4.0 Req 1.3.2",
            "title": "No explicit deny-all rule found",
            "description": (
                "PCI DSS Req 1.3.2 requires that firewall policies deny all traffic "
                "that is not explicitly permitted. No deny-all catch-all rule was found "
                "at the end of the policy list. This means any traffic not matching a "
                "permit rule may default to an implicit permit depending on the platform."
            ),
            "affected_rules": [],
            "remediation": (
                "Add an explicit 'deny any any' rule as the last policy in the list "
                "to ensure all unmatched traffic is blocked."
            ),
        })
    return findings


def _check_internet_to_cde(rules: list[dict], cde_seeds: list[str]) -> list[dict]:
    """Req 1.3.3 — No direct permitted path from internet to CDE."""
    findings = []
    affected = []
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        src_addrs = rule.get("src_addrs", [])
        dst_addrs = rule.get("dst_addrs", [])
        if any(_is_internet(s) for s in src_addrs) and _overlaps_any_cde(dst_addrs, cde_seeds):
            affected.append(rule.get("policy_id", "?"))

    if affected:
        findings.append({
            "id": "GAP-INET-TO-CDE",
            "severity": "critical",
            "requirement": "PCI DSS v4.0 Req 1.3.3",
            "title": "Direct internet access to CDE systems detected",
            "description": (
                f"Rules {', '.join(affected)} permit traffic from internet source addresses "
                "directly to systems you identified as CDE. PCI DSS prohibits direct "
                "internet connectivity to the CDE without an intervening DMZ or security control."
            ),
            "affected_rules": affected,
            "remediation": (
                "Introduce a DMZ tier between internet-facing services and CDE systems. "
                "Replace direct internet-to-CDE permit rules with rules that only allow "
                "traffic from the DMZ/proxy layer."
            ),
        })
    return findings


def _check_broad_inbound(rules: list[dict]) -> list[dict]:
    """Req 1.3.5 — Flag overly broad inbound permit rules (any src, any port)."""
    findings = []
    affected = []
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        src_addrs = rule.get("src_addrs", [])
        services = rule.get("services", [])
        # 'any' source AND 'ALL' services
        if any(_is_any(s) for s in src_addrs) and any(s.upper() in ("ALL", "ANY", "0/0") for s in services):
            affected.append(rule.get("policy_id", "?"))

    if affected:
        findings.append({
            "id": "GAP-BROAD-INBOUND",
            "severity": "high",
            "requirement": "PCI DSS v4.0 Req 1.3.5",
            "title": "Overly broad permit rules (any source, any service)",
            "description": (
                f"Rules {', '.join(affected)} permit traffic from any source on any service. "
                "PCI DSS requires that only explicitly necessary traffic is allowed. "
                "Any-any rules significantly expand the attack surface."
            ),
            "affected_rules": affected,
            "remediation": (
                "Replace any-any permit rules with specific source IP/subnet and "
                "service restrictions. If broad access is required temporarily, "
                "document the business justification and set a review date."
            ),
        })
    return findings


def _check_cde_outbound(rules: list[dict], cde_seeds: list[str]) -> list[dict]:
    """Req 1.4.2 — CDE systems should not have unrestricted outbound internet access."""
    findings = []
    affected = []
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        src_addrs = rule.get("src_addrs", [])
        dst_addrs = rule.get("dst_addrs", [])
        services = rule.get("services", [])
        if (
            _overlaps_any_cde(src_addrs, cde_seeds)
            and any(_is_internet(d) for d in dst_addrs)
            and any(s.upper() in ("ALL", "ANY") for s in services)
        ):
            affected.append(rule.get("policy_id", "?"))

    if affected:
        findings.append({
            "id": "GAP-CDE-OUTBOUND",
            "severity": "high",
            "requirement": "PCI DSS v4.0 Req 1.4.2",
            "title": "CDE systems have unrestricted outbound internet access",
            "description": (
                f"Rules {', '.join(affected)} permit unrestricted outbound internet traffic "
                "from CDE systems. PCI DSS requires that outbound traffic from CDE is "
                "restricted to only what is necessary."
            ),
            "affected_rules": affected,
            "remediation": (
                "Restrict CDE outbound rules to specific destination IPs/ports required "
                "for business operations (e.g., payment processor IPs, patch servers). "
                "Block all other outbound traffic from CDE."
            ),
        })
    return findings


def _check_rule_comments(rules: list[dict]) -> list[dict]:
    """Req 1.2.5 — All rules should have documented justification."""
    findings = []
    missing = [
        rule.get("policy_id", "?")
        for rule in rules
        if not rule.get("comment") and rule.get("action") == "permit"
    ]
    pct = (len(missing) / len(rules) * 100) if rules else 0

    if pct > 30:  # only flag if >30% of rules are missing comments
        findings.append({
            "id": "GAP-RULE-COMMENTS",
            "severity": "low",
            "requirement": "PCI DSS v4.0 Req 1.2.5",
            "title": f"{len(missing)} of {len(rules)} rules have no justification comment",
            "description": (
                f"PCI DSS Req 1.2.5 requires that all firewall rules have documented "
                f"business justification. {len(missing)} rules ({pct:.0f}%) are missing comments."
            ),
            "affected_rules": missing[:20],  # cap list length
            "remediation": (
                "Add a comment/description to each firewall rule documenting the "
                "business reason, approver, and review date. Use change management "
                "processes to ensure all new rules are documented at creation time."
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# Static question generator
# ---------------------------------------------------------------------------

def generate_questions(
    rules: list[dict],
    scope_nodes: list[dict],
    cde_seeds: list[str],
) -> list[dict]:
    """Generate static clarifying questions based on rule patterns."""
    questions: list[dict] = []
    seen_texts: set[str] = set()

    def add_q(category: str, text: str, rule_id: str | None = None, context: dict | None = None) -> None:
        if text not in seen_texts:
            seen_texts.add(text)
            questions.append({
                "id": str(uuid.uuid4())[:8],
                "category": category,
                "text": text,
                "rule_id": rule_id,
                "context": context or {},
            })

    for rule in rules:
        rid = rule.get("policy_id", "?")
        src_addrs = rule.get("src_addrs", [])
        dst_addrs = rule.get("dst_addrs", [])
        services = rule.get("services", [])
        action = rule.get("action", "permit")

        if action != "permit":
            continue

        # Q1: Any-to-any permit on internal subnets
        if (
            any(_is_any(s) for s in src_addrs)
            and any(_is_any(d) for d in dst_addrs)
            and any(s.upper() in ("ALL", "ANY") for s in services)
        ):
            add_q(
                "ambiguity",
                f"Rule #{rid} permits ANY source to reach ANY destination on ALL services. "
                "What is the business purpose of this rule? Is it a temporary admin override "
                "that should be removed?",
                rule_id=rid,
            )

        # Q2: External access to internal ranges on card-processing ports
        for src in src_addrs:
            for dst in dst_addrs:
                for svc in services:
                    port = _extract_port(svc)
                    if (
                        _is_internet(src)
                        and _is_private(dst)
                        and port in _CARD_PROCESSING_PORTS
                    ):
                        add_q(
                            "cde_id",
                            f"Rule #{rid} allows external traffic to {dst} on port {port} "
                            "(commonly used for card transaction processing). "
                            "Does this subnet process, store, or transmit cardholder data?",
                            rule_id=rid,
                            context={"dst": dst, "port": port},
                        )

        # Q3: ANY source to private subnet (not CDE, possibly missed)
        for dst in dst_addrs:
            if (
                any(_is_any(s) for s in src_addrs)
                and _is_private(dst)
                and not _overlaps_any_cde([dst], cde_seeds)
            ):
                add_q(
                    "ambiguity",
                    f"Rule #{rid} permits any source to reach {dst}. "
                    "What is this subnet used for? Should it be classified as CDE or connected?",
                    rule_id=rid,
                    context={"dst": dst},
                )
                break  # one question per rule

        # Q4: Access to known payment processor ranges
        for dst in dst_addrs:
            dst_net = _parse_net(dst)
            if dst_net is None:
                continue
            for payment_range in _KNOWN_PAYMENT_RANGES:
                payment_net = _parse_net(payment_range)
                if payment_net and dst_net.overlaps(payment_net):
                    add_q(
                        "cde_id",
                        f"Rule #{rid} permits access to {dst}, which overlaps with a known "
                        "payment network range. Is the source system involved in "
                        "cardholder data flow?",
                        rule_id=rid,
                        context={"dst": dst},
                    )
                    break

    # Q5: Scope confirmation for connected nodes — ask user to confirm or reclassify
    connected_nodes = [n for n in scope_nodes if n.get("scope_status") == "connected"]
    for node in connected_nodes[:5]:  # limit to 5 to avoid overwhelming the user
        ip = node.get("ip", "")
        if ip and not _is_any(ip):
            add_q(
                "segmentation",
                f"{ip} was automatically classified as 'connected to CDE' because a "
                "permitted traffic path exists between it and your CDE systems. "
                "Please confirm: does this system have security controls limiting its "
                "access to the CDE?",
                context={"ip": ip, "rule_ids": node.get("rule_ids", [])},
            )

    # Q6: No rules between interfaces (possible missing segmentation)
    intfs = {r.get("src_intf") for r in rules if r.get("src_intf")} | \
            {r.get("dst_intf") for r in rules if r.get("dst_intf")}
    if len(intfs) >= 2:
        has_wireless = any("wifi" in i.lower() or "wlan" in i.lower() or "wireless" in i.lower()
                           for i in intfs if i)
        if has_wireless:
            add_q(
                "segmentation",
                "A wireless interface was detected in the config. PCI DSS requires "
                "that wireless networks be isolated from the CDE. Are there firewall "
                "rules separating the wireless segment from CDE systems?",
                context={"interfaces": list(intfs)},
            )

    # Q7: Rules without deny-all
    permit_count = sum(1 for r in rules if r.get("action") == "permit")
    deny_count = sum(1 for r in rules if r.get("action") == "deny")
    if deny_count == 0 and permit_count > 0:
        add_q(
            "missing_rule",
            "No deny rules were found in this configuration. "
            "Is there a deny-all-by-default enforced at a different layer "
            "(e.g., a separate upstream firewall or ACL)?",
        )

    return questions


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_gap_analysis(
    rules: list[dict],
    cde_seeds: list[str],
    scope_nodes: list[dict],
) -> dict:
    """
    Run all gap checks and generate questions.

    Returns:
      {
        "gap_findings": list[dict],
        "questions": list[dict],
      }
    """
    findings: list[dict] = []
    findings.extend(_check_deny_all(rules))
    findings.extend(_check_internet_to_cde(rules, cde_seeds))
    findings.extend(_check_broad_inbound(rules))
    findings.extend(_check_cde_outbound(rules, cde_seeds))
    findings.extend(_check_rule_comments(rules))

    questions = generate_questions(rules, scope_nodes, cde_seeds)

    return {
        "gap_findings": findings,
        "questions": questions,
    }
