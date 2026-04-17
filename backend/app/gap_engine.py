"""
PCI DSS v4.0 Gap Analysis Engine (Phase 2 — static checks).

Performs 10 gap checks covering Requirement 1.2–1.5 and generates
static clarifying questions based on rule patterns.

Checks implemented:
  1. Req 1.2.5 — Rules missing business-justification comments
  2. Req 1.2.6 — Insecure protocols (Telnet, FTP, rsh, TFTP) permitted
  3. Req 1.3.1 — All-service inbound access to CDE from internal networks
  4. Req 1.3.2 — No explicit deny-all default policy
  5. Req 1.3.3 — Wireless interface has direct permit to CDE
  6. Req 1.3.5 — Overly broad any-source/any-service inbound permit rules
  7. Req 1.4.2 — CDE systems have unrestricted outbound internet access
  8. Req 1.4.3 — Anti-spoofing: private IPs permitted from external interfaces
  9. Req 1.4.5 — CDE systems reachable from internet without NAT
 10. Req 1.3.3 — Direct internet access to CDE (GAP-INET-TO-CDE)

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

_INSECURE_PORTS: dict[str, str] = {
    "20": "FTP Data",
    "21": "FTP Control",
    "23": "Telnet",
    "69": "TFTP",
    "513": "rlogin",
    "514": "rsh/rexec",
}
_INSECURE_SERVICE_NAMES = frozenset({"telnet", "ftp", "tftp", "rlogin", "rsh", "rexec"})

_EXTERNAL_INTF_KEYWORDS = ("wan", "untrust", "external", "internet", "outside", "uplink", "inet")

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


def _is_external_intf(intf: str | None) -> bool:
    if not intf:
        return False
    lower = intf.lower()
    return any(kw in lower for kw in _EXTERNAL_INTF_KEYWORDS)


def _is_insecure_service(svc: str) -> tuple[bool, str]:
    """Return (True, label) if svc matches a known insecure port or service name."""
    port = _extract_port(svc)
    if port and port in _INSECURE_PORTS:
        return True, f"{_INSECURE_PORTS[port]} (port {port})"
    if svc.lower() in _INSECURE_SERVICE_NAMES:
        return True, svc.upper()
    return False, ""


def _check_insecure_protocols(rules: list[dict]) -> list[dict]:
    """Req 1.2.6 — Known insecure protocols (Telnet, FTP, rsh, TFTP) are permitted."""
    findings = []
    affected: list[str] = []
    proto_found: set[str] = set()
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        for svc in rule.get("services", []):
            hit, label = _is_insecure_service(svc)
            if hit:
                affected.append(rule.get("policy_id", "?"))
                proto_found.add(label)
                break  # one match per rule
    if affected:
        protos = ", ".join(sorted(proto_found))
        findings.append({
            "id": "GAP-INSECURE-PROTO",
            "severity": "high",
            "requirement": "PCI DSS v4.0 Req 1.2.6",
            "title": f"Insecure protocols permitted: {protos}",
            "description": (
                f"PCI DSS Req 1.2.6 requires that insecure services are not permitted unless "
                f"additional security features mitigate the risk. Rules {', '.join(affected)} "
                f"permit known insecure protocols: {protos}. These protocols transmit data "
                "in cleartext and are prohibited in or adjacent to CDE environments."
            ),
            "affected_rules": affected,
            "remediation": (
                "Disable or block Telnet (23), FTP (20/21), TFTP (69), rsh (514), and "
                "rlogin (513). Replace with encrypted alternatives: SSH (22) instead of "
                "Telnet/rsh, SFTP/FTPS instead of FTP."
            ),
        })
    return findings


def _check_broad_internal_cde(rules: list[dict], cde_seeds: list[str]) -> list[dict]:
    """Req 1.3.1 — Inbound access to CDE must be restricted to only what is necessary."""
    if not cde_seeds:
        return []
    findings = []
    affected: list[str] = []
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        src_addrs = rule.get("src_addrs", [])
        dst_addrs = rule.get("dst_addrs", [])
        services = rule.get("services", [])
        # Private/any source → CDE destination on any/all services
        if (
            any(_is_any(s) or _is_private(s) for s in src_addrs)
            and not any(_is_internet(s) for s in src_addrs)  # internet→CDE caught by GAP-INET-TO-CDE
            and _overlaps_any_cde(dst_addrs, cde_seeds)
            and any(s.upper() in ("ALL", "ANY") for s in services)
        ):
            affected.append(rule.get("policy_id", "?"))
    if affected:
        findings.append({
            "id": "GAP-BROAD-INTERNAL-CDE",
            "severity": "medium",
            "requirement": "PCI DSS v4.0 Req 1.3.1",
            "title": "Unrestricted all-service access to CDE from internal networks",
            "description": (
                f"Rules {', '.join(affected)} permit traffic from internal or broad source "
                "addresses to CDE systems on ALL services. PCI DSS Req 1.3.1 requires that "
                "inbound traffic to the CDE is restricted to only what is necessary. "
                "All-service access to CDE from internal networks violates least-privilege."
            ),
            "affected_rules": affected,
            "remediation": (
                "Replace all-service CDE inbound rules with specific port/protocol "
                "restrictions. Only allow the exact services each CDE system needs "
                "(e.g., tcp/443 for a payment web server, tcp/1433 for a database). "
                "Segment access by source subnet."
            ),
        })
    return findings


def _check_anti_spoofing(rules: list[dict]) -> list[dict]:
    """Req 1.4.3 — Anti-spoofing: inbound from external interfaces must not permit private source IPs."""
    findings = []
    affected: list[str] = []
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        src_intf = rule.get("src_intf")
        if not _is_external_intf(src_intf):
            continue
        src_addrs = rule.get("src_addrs", [])
        # External interface but source is a private RFC1918 range — spoofing risk
        if any(_is_private(s) for s in src_addrs):
            affected.append(rule.get("policy_id", "?"))
    if affected:
        findings.append({
            "id": "GAP-SPOOF",
            "severity": "high",
            "requirement": "PCI DSS v4.0 Req 1.4.3",
            "title": "Anti-spoofing controls missing: private source IPs permitted from external interface",
            "description": (
                f"Rules {', '.join(affected)} permit traffic arriving on an external/WAN "
                "interface with RFC1918 private source addresses. PCI DSS Req 1.4.3 requires "
                "anti-spoofing measures to detect and block forged source IP addresses. "
                "Allowing private IPs inbound from untrusted interfaces enables IP spoofing."
            ),
            "affected_rules": affected,
            "remediation": (
                "Add ingress ACL rules on all external/WAN interfaces to block traffic "
                "with RFC1918 source addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). "
                "Consider implementing Unicast Reverse Path Forwarding (uRPF) on "
                "internet-facing interfaces."
            ),
        })
    return findings


def _check_cde_no_nat(rules: list[dict], cde_seeds: list[str]) -> list[dict]:
    """Req 1.4.5 — CDE IP addresses must not be disclosed to untrusted networks (NAT required)."""
    if not cde_seeds:
        return []
    findings = []
    affected: list[str] = []
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        src_addrs = rule.get("src_addrs", [])
        dst_addrs = rule.get("dst_addrs", [])
        nat = rule.get("nat", True)  # assume NAT present unless explicitly false
        if (
            any(_is_internet(s) for s in src_addrs)
            and _overlaps_any_cde(dst_addrs, cde_seeds)
            and not nat
        ):
            affected.append(rule.get("policy_id", "?"))
    if affected:
        findings.append({
            "id": "GAP-CDE-NO-NAT",
            "severity": "medium",
            "requirement": "PCI DSS v4.0 Req 1.4.5",
            "title": "CDE systems reachable from internet without NAT (internal IPs exposed)",
            "description": (
                f"Rules {', '.join(affected)} permit inbound internet traffic directly to "
                "CDE systems with NAT disabled. PCI DSS Req 1.4.5 requires that internal IP "
                "addresses and routing information of CDE systems are not disclosed to "
                "untrusted networks. Exposing real CDE IP addresses aids attacker reconnaissance."
            ),
            "affected_rules": affected,
            "remediation": (
                "Enable NAT/PAT so that CDE systems use RFC1918 private addresses internally "
                "and only public-facing load balancer or proxy IPs are visible from the internet. "
                "Ensure no static 1:1 NAT maps directly expose CDE IPs without additional controls."
            ),
        })
    return findings


def _check_wireless_cde_segment(rules: list[dict], cde_seeds: list[str]) -> list[dict]:
    """Req 1.3.3 — NSC must be installed between wireless networks and the CDE."""
    if not cde_seeds:
        return []
    # Collect wireless source interfaces
    wireless_intfs: set[str] = set()
    for rule in rules:
        for key in ("src_intf", "dst_intf"):
            intf = rule.get(key) or ""
            if any(w in intf.lower() for w in ("wifi", "wlan", "wireless")):
                wireless_intfs.add(intf)
    if not wireless_intfs:
        return []
    # Flag any permit rule from wireless interface to CDE
    affected: list[str] = []
    for rule in rules:
        if rule.get("action") != "permit":
            continue
        if rule.get("src_intf") in wireless_intfs:
            if _overlaps_any_cde(rule.get("dst_addrs", []), cde_seeds):
                affected.append(rule.get("policy_id", "?"))
    if not affected:
        return []
    return [{
        "id": "GAP-WIRELESS-CDE",
        "severity": "critical",
        "requirement": "PCI DSS v4.0 Req 1.3.3",
        "title": "Wireless network has direct permitted access to CDE",
        "description": (
            f"Rules {', '.join(affected)} permit traffic from wireless interface(s) "
            f"({', '.join(sorted(wireless_intfs))}) directly to CDE systems. "
            "PCI DSS Req 1.3.3 requires that NSCs are installed between all wireless "
            "networks and the CDE regardless of whether the wireless network is trusted."
        ),
        "affected_rules": affected,
        "remediation": (
            "Place wireless networks in a separate VLAN/segment with no direct permit "
            "rules to CDE systems. Route wireless traffic through security controls "
            "(IDS/IPS, next-gen firewall policy) before it can reach any CDE resource. "
            "Add explicit deny rules from wireless interfaces to CDE subnets."
        ),
    }]


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
# Answer processing helpers
# ---------------------------------------------------------------------------

_POSITIVE_WORDS = frozenset({"yes", "yep", "yeah", "correct", "true", "confirmed", "affirmative"})
_UPSTREAM_DENY_WORDS = frozenset({"upstream", "acl", "layer", "separate", "external", "another"})


def _answer_is_positive(text: str) -> bool:
    """Return True when an answer begins with or contains a clear affirmative."""
    lower = text.strip().lower()
    first_word = lower.split()[0] if lower.split() else ""
    return first_word in _POSITIVE_WORDS or any(w in lower for w in _POSITIVE_WORDS)


def extract_answer_driven_cde_seeds(
    questions: list[dict],
    answers: dict[str, str],
) -> list[str]:
    """
    Scan answered *cde_id* questions.  When the user's answer is clearly
    affirmative, the destination subnet from that question's context is
    treated as an additional confirmed CDE seed.
    """
    extra_seeds: list[str] = []
    for q in questions:
        qid = q.get("id", "")
        answer = answers.get(qid, "").strip()
        if not answer:
            continue
        if q.get("category") == "cde_id" and _answer_is_positive(answer):
            dst = q.get("context", {}).get("dst")
            if dst and isinstance(dst, str):
                extra_seeds.append(dst)
    return extra_seeds


def refine_findings_with_answers(
    findings: list[dict],
    questions: list[dict],
    answers: dict[str, str],
) -> list[dict]:
    """
    Post-process gap findings using the user's answers to clarifying questions.

    Current refinements:
    - GAP-DENY-ALL: suppress when a *missing_rule* question is answered with
      affirmation of an upstream / out-of-band deny-all.
    - Any finding: annotate its description when the user answered an
      *ambiguity* question that references the same rule(s).
    """
    # Build lookup: question_id → question
    q_by_id = {q["id"]: q for q in questions}

    # Determine whether user confirmed an upstream deny-all
    upstream_deny_confirmed = False
    for q in questions:
        if q.get("category") != "missing_rule":
            continue
        answer = answers.get(q["id"], "").strip().lower()
        if not answer:
            continue
        if _answer_is_positive(answer) or any(w in answer for w in _UPSTREAM_DENY_WORDS):
            upstream_deny_confirmed = True
            break

    # Collect rule-level answers from ambiguity questions
    rule_answer_notes: dict[str, str] = {}  # rule_id → answer text
    for q in questions:
        if q.get("category") != "ambiguity":
            continue
        rid = q.get("rule_id")
        answer = answers.get(q["id"], "").strip()
        if rid and answer:
            rule_answer_notes[str(rid)] = answer

    refined: list[dict] = []
    for finding in findings:
        fid = finding.get("id", "")

        # Suppress deny-all gap when user confirmed an upstream control
        if fid == "GAP-DENY-ALL" and upstream_deny_confirmed:
            continue

        # Annotate findings whose affected rules have been explained by the user
        affected = finding.get("affected_rules", [])
        notes = [rule_answer_notes[r] for r in affected if r in rule_answer_notes]
        if notes:
            annotated = dict(finding)
            note_text = "; ".join(notes[:3])  # cap at 3 notes
            annotated["description"] = (
                finding["description"]
                + f"\n\n**User context:** {note_text}"
            )
            refined.append(annotated)
        else:
            refined.append(finding)

    return refined


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_gap_analysis(
    rules: list[dict],
    cde_seeds: list[str],
    scope_nodes: list[dict],
    answers: dict[str, str] | None = None,
    questions: list[dict] | None = None,
) -> dict:
    """
    Run all gap checks and generate questions.

    When *answers* and *questions* are provided (i.e. on a re-run after the
    user answered clarifying questions), findings are post-processed to
    incorporate the user's input.

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
    findings.extend(_check_insecure_protocols(rules))
    findings.extend(_check_broad_internal_cde(rules, cde_seeds))
    findings.extend(_check_anti_spoofing(rules))
    findings.extend(_check_cde_no_nat(rules, cde_seeds))
    findings.extend(_check_wireless_cde_segment(rules, cde_seeds))

    if answers and questions:
        findings = refine_findings_with_answers(findings, questions, answers)

    new_questions = generate_questions(rules, scope_nodes, cde_seeds)

    return {
        "gap_findings": findings,
        "questions": new_questions,
    }
