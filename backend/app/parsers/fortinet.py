"""
Fortinet FortiGate config parser.

Handles the hierarchical `config / edit / set / next / end` format produced by
`show full-configuration` or individual `config firewall policy` exports.

Returns a list of normalized rule dicts:
  {
    "policy_id": str,
    "name": str | None,
    "src_intf": str | None,
    "dst_intf": str | None,
    "src_addrs": list[str],   # CIDR strings or "all"
    "dst_addrs": list[str],
    "services": list[str],    # "proto/port" or "ALL"
    "action": "permit" | "deny",
    "nat": bool,
    "log_traffic": bool,
    "comment": str | None,
    "raw": dict,
  }

Also returns the address object table, address group table, and interface table
as side-band data used by the scope engine.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


# ---------------------------------------------------------------------------
# Tokenizer / block parser
# ---------------------------------------------------------------------------

def _parse_blocks(text: str) -> dict[str, Any]:
    """
    Parse FortiGate config text into a nested dict of config sections.
    Top-level keys are config block names (e.g. "firewall policy").
    Values are dicts keyed by edit-id, each containing a dict of set values.
    """
    lines = [l.rstrip() for l in text.splitlines()]
    stack: list[dict[str, Any]] = [{}]
    section_stack: list[str] = ["__root__"]
    current_edit: str | None = None

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if not line or line.startswith("#"):
            i += 1
            continue

        if line.startswith("config "):
            section_name = line[7:].strip()
            new_section: dict[str, Any] = {}
            stack[-1].setdefault(section_name, {})
            stack.append(new_section)
            section_stack.append(section_name)
            current_edit = None

        elif line.startswith("edit "):
            raw_id = line[5:].strip().strip('"')
            current_edit = raw_id
            stack[-1].setdefault(current_edit, {})

        elif line.startswith("set ") and current_edit is not None:
            parts = line[4:].split(None, 1)
            key = parts[0]
            val = parts[1].strip('"') if len(parts) > 1 else ""
            stack[-1][current_edit][key] = val

        elif line == "next":
            current_edit = None

        elif line == "end":
            finished = stack.pop()
            name = section_stack.pop()
            if stack:
                parent = stack[-1]
                # merge finished block under its name
                existing = parent.get(name)
                if isinstance(existing, dict):
                    existing.update(finished)
                else:
                    parent[name] = finished
            current_edit = None

        i += 1

    return stack[0] if stack else {}


# ---------------------------------------------------------------------------
# Address object resolution
# ---------------------------------------------------------------------------

def _mask_to_prefix(mask: str) -> int:
    """Convert dotted subnet mask to prefix length."""
    try:
        return sum(bin(int(x)).count("1") for x in mask.split("."))
    except Exception:
        return 32


def _resolve_addresses(
    name: str,
    addr_table: dict[str, Any],
    grp_table: dict[str, Any],
    _depth: int = 0,
) -> list[str]:
    """Resolve a FortiGate address name to a list of CIDR strings."""
    if _depth > 10:
        return [name]
    name = name.strip('"')
    if name.lower() in ("all", "any"):
        return ["0.0.0.0/0"]

    # Check if it's already a CIDR / IP
    try:
        ipaddress.ip_network(name, strict=False)
        return [name]
    except ValueError:
        pass

    # Check address group first
    if name in grp_table:
        members = grp_table[name].get("member", "").split()
        result: list[str] = []
        for m in members:
            m = m.strip('"')
            result.extend(_resolve_addresses(m, addr_table, grp_table, _depth + 1))
        return result or [name]

    # Check address object
    if name in addr_table:
        obj = addr_table[name]
        obj_type = obj.get("type", "ipmask")
        subnet = obj.get("subnet", "")
        if subnet:
            parts = subnet.split()
            if len(parts) == 2:
                prefix = _mask_to_prefix(parts[1])
                try:
                    net = ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                    return [str(net)]
                except ValueError:
                    pass
            elif len(parts) == 1:
                try:
                    net = ipaddress.ip_network(parts[0], strict=False)
                    return [str(net)]
                except ValueError:
                    pass
        fqdn = obj.get("fqdn", "")
        if fqdn:
            return [f"fqdn:{fqdn}"]
        wildcard = obj.get("wildcard", "")
        if wildcard:
            return [f"wildcard:{wildcard}"]

    # Fall back to name as-is (unresolvable)
    return [name]


# ---------------------------------------------------------------------------
# Service resolution
# ---------------------------------------------------------------------------

_BUILTIN_SERVICES: dict[str, list[str]] = {
    "ALL": ["ALL"],
    "ANY": ["ALL"],
    "HTTP": ["tcp/80"],
    "HTTPS": ["tcp/443"],
    "SSH": ["tcp/22"],
    "FTP": ["tcp/21"],
    "SMTP": ["tcp/25"],
    "DNS": ["tcp/53", "udp/53"],
    "TELNET": ["tcp/23"],
    "IMAP": ["tcp/143"],
    "POP3": ["tcp/110"],
    "LDAP": ["tcp/389"],
    "LDAPS": ["tcp/636"],
    "RDP": ["tcp/3389"],
    "MYSQL": ["tcp/3306"],
    "MSSQL": ["tcp/1433"],
    "ORACLE": ["tcp/1521"],
    "NTP": ["udp/123"],
    "SNMP": ["udp/161"],
    "SYSLOG": ["udp/514"],
    "RADIUS": ["udp/1812"],
    "PING": ["icmp/0"],
    "ICMP": ["icmp/0"],
}


def _resolve_service(
    name: str,
    svc_table: dict[str, Any],
    svcgrp_table: dict[str, Any],
    _depth: int = 0,
) -> list[str]:
    """Resolve a FortiGate service name to list of 'proto/port' strings."""
    if _depth > 10:
        return [name]
    name = name.strip('"').upper()
    if name in _BUILTIN_SERVICES:
        return _BUILTIN_SERVICES[name]

    # Service group
    if name in svcgrp_table:
        members = svcgrp_table[name].get("member", "").split()
        result: list[str] = []
        for m in members:
            result.extend(_resolve_service(m, svc_table, svcgrp_table, _depth + 1))
        return result or [name]

    # Custom service
    if name in svc_table:
        obj = svc_table[name]
        proto = obj.get("protocol", "TCP").upper()
        results: list[str] = []
        if proto in ("TCP", "TCP/UDP/SCTP"):
            tcp_range = obj.get("tcp-portrange", "")
            for pr in tcp_range.split():
                results.append(f"tcp/{pr}")
        if proto in ("UDP", "TCP/UDP/SCTP"):
            udp_range = obj.get("udp-portrange", "")
            for pr in udp_range.split():
                results.append(f"udp/{pr}")
        if proto == "ICMP":
            results.append("icmp/0")
        return results or [name.lower()]

    return [name.lower()]


# ---------------------------------------------------------------------------
# Interface table
# ---------------------------------------------------------------------------

def _build_interface_table(root: dict[str, Any]) -> dict[str, str]:
    """Return {interface_name: ip_cidr} from 'system interface' config."""
    intf_table: dict[str, str] = {}
    intf_section = root.get("system interface", {})
    for intf_name, data in intf_section.items():
        if not isinstance(data, dict):
            continue
        ip_mask = data.get("ip", "")
        if ip_mask:
            parts = ip_mask.split()
            if len(parts) == 2:
                try:
                    prefix = _mask_to_prefix(parts[1])
                    net = ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                    intf_table[intf_name] = str(net)
                except ValueError:
                    intf_table[intf_name] = ip_mask
            else:
                intf_table[intf_name] = ip_mask
    return intf_table


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_fortinet(text: str) -> dict:
    """
    Parse a FortiGate full-configuration text.

    Returns:
      {
        "rules": list[dict],          # normalized rules
        "interfaces": dict,           # name → CIDR
        "addresses": dict,            # raw address objects
        "parse_errors": list[str],
      }
    """
    root = _parse_blocks(text)
    errors: list[str] = []

    addr_table: dict[str, Any] = root.get("firewall address", {})
    grp_table: dict[str, Any] = root.get("firewall addrgrp", {})
    svc_table: dict[str, Any] = root.get("firewall service custom", {})
    svcgrp_table: dict[str, Any] = root.get("firewall service group", {})
    policy_section: dict[str, Any] = root.get("firewall policy", {})
    interface_table = _build_interface_table(root)

    rules: list[dict] = []

    for policy_id, data in policy_section.items():
        if not isinstance(data, dict):
            continue
        try:
            raw = dict(data)

            # Resolve source addresses
            src_raw = raw.get("srcaddr", "all")
            src_names = [s.strip('"') for s in src_raw.split() if s.strip('"')]
            if not src_names:
                src_names = ["all"]
            src_addrs: list[str] = []
            for sn in src_names:
                src_addrs.extend(_resolve_addresses(sn, addr_table, grp_table))

            # Resolve destination addresses
            dst_raw = raw.get("dstaddr", "all")
            dst_names = [s.strip('"') for s in dst_raw.split() if s.strip('"')]
            if not dst_names:
                dst_names = ["all"]
            dst_addrs: list[str] = []
            for dn in dst_names:
                dst_addrs.extend(_resolve_addresses(dn, addr_table, grp_table))

            # Resolve services
            svc_raw = raw.get("service", "ALL")
            svc_names = [s.strip('"') for s in svc_raw.split() if s.strip('"')]
            if not svc_names:
                svc_names = ["ALL"]
            services: list[str] = []
            for sv in svc_names:
                services.extend(_resolve_service(sv, svc_table, svcgrp_table))

            action_raw = raw.get("action", "accept").lower()
            action = "deny" if action_raw in ("deny", "block", "drop") else "permit"

            log_raw = raw.get("logtraffic", raw.get("log-traffic", "utm")).lower()
            log_traffic = log_raw not in ("disable", "none", "")

            rule = {
                "policy_id": str(policy_id),
                "name": raw.get("name"),
                "src_intf": raw.get("srcintf"),
                "dst_intf": raw.get("dstintf"),
                "src_addrs": src_addrs,
                "dst_addrs": dst_addrs,
                "services": services,
                "action": action,
                "nat": raw.get("nat", "disable").lower() == "enable",
                "log_traffic": log_traffic,
                "comment": raw.get("comments") or raw.get("comment"),
                "raw": raw,
            }
            rules.append(rule)
        except Exception as exc:
            errors.append(f"Policy {policy_id}: {exc}")

    return {
        "rules": rules,
        "interfaces": interface_table,
        "addresses": {k: v for k, v in addr_table.items() if isinstance(v, dict)},
        "parse_errors": errors,
    }
