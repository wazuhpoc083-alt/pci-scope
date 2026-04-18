"""
Cisco ASA firewall config parser.

Handles the text format produced by:
  - ``show running-config`` on Cisco ASA/ASASM
  - ``write terminal`` output
  - Saved startup configs

Returns the same normalized rule dict format as other parsers:
  {
    "policy_id": str,
    "name": str | None,
    "src_intf": str | None,
    "dst_intf": str | None,
    "src_addrs": list[str],   # CIDR strings or "0.0.0.0/0"
    "dst_addrs": list[str],
    "services": list[str],    # "proto/port" or "ALL"
    "action": "permit" | "deny",
    "nat": bool,
    "log_traffic": bool,
    "comment": str | None,
    "raw": dict,
  }

Also returns the address object table and interface table.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


# ---------------------------------------------------------------------------
# Subnet mask → prefix length conversion
# ---------------------------------------------------------------------------

def _mask_to_prefix(mask: str) -> int:
    """Convert dotted-decimal subnet mask to prefix length."""
    try:
        packed = 0
        for octet in mask.split("."):
            packed = (packed << 8) | int(octet)
        # Count leading 1-bits
        return bin(packed).count("1")
    except Exception:
        return 32


def _ip_mask_to_cidr(ip: str, mask: str) -> str:
    """Convert 'ip mask' pair to CIDR notation."""
    try:
        prefix = _mask_to_prefix(mask)
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except ValueError:
        return f"{ip}/{mask}"


# ---------------------------------------------------------------------------
# Object / object-group tables
# ---------------------------------------------------------------------------

def _build_object_tables(lines: list[str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """
    Parse object and object-group definitions.

    Returns:
      net_objects   – {name: [cidr, ...]}
      svc_objects   – {name: [proto/port, ...]}
      net_groups    – {name: [cidr, ...]}   (flattened)
      svc_groups    – {name: [proto/port, ...]}  (flattened)
    """
    net_objects: dict[str, list[str]] = {}
    svc_objects: dict[str, list[str]] = {}
    net_groups: dict[str, list[str]] = {}
    svc_groups: dict[str, list[str]] = {}

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # ---- object network <name> ----
        m = re.match(r"^object network (\S+)", stripped)
        if m:
            name = m.group(1)
            addrs: list[str] = []
            i += 1
            while i < len(lines):
                sub = lines[i]
                if sub and not sub[0].isspace():
                    break
                sub = sub.strip()
                if sub.startswith("host "):
                    host = sub.split()[1]
                    addrs.append(f"{host}/32")
                elif sub.startswith("subnet "):
                    parts = sub.split()
                    if len(parts) >= 3:
                        addrs.append(_ip_mask_to_cidr(parts[1], parts[2]))
                elif sub.startswith("range "):
                    parts = sub.split()
                    if len(parts) >= 3:
                        addrs.append(f"range:{parts[1]}-{parts[2]}")
                elif sub.startswith("fqdn "):
                    parts = sub.split()
                    fqdn_val = parts[-1]
                    addrs.append(f"fqdn:{fqdn_val}")
                i += 1
            net_objects[name] = addrs or ["0.0.0.0/0"]
            continue

        # ---- object service <name> ----
        m = re.match(r"^object service (\S+)", stripped)
        if m:
            name = m.group(1)
            services: list[str] = []
            i += 1
            while i < len(lines):
                sub = lines[i]
                if sub and not sub[0].isspace():
                    break
                sub = sub.strip()
                if sub.startswith("service "):
                    svc = _parse_service_spec(sub.split(None, 1)[1] if " " in sub else "")
                    services.extend(svc)
                i += 1
            svc_objects[name] = services or ["ALL"]
            continue

        # ---- object-group network <name> ----
        m = re.match(r"^object-group network (\S+)", stripped)
        if m:
            name = m.group(1)
            members: list[str] = []
            i += 1
            while i < len(lines):
                sub = lines[i]
                if sub and not sub[0].isspace():
                    break
                sub = sub.strip()
                if sub.startswith("network-object host "):
                    parts = sub.split()
                    if len(parts) >= 3:
                        members.append(f"{parts[2]}/32")
                elif sub.startswith("network-object object "):
                    ref = sub.split(None, 2)[2].strip()
                    members.append(f"__net_obj:{ref}")
                elif sub.startswith("network-object "):
                    parts = sub.split()
                    if len(parts) >= 3:
                        members.append(_ip_mask_to_cidr(parts[1], parts[2]))
                elif sub.startswith("group-object "):
                    ref = sub.split(None, 1)[1].strip()
                    members.append(f"__net_grp:{ref}")
                i += 1
            net_groups[name] = members
            continue

        # ---- object-group service <name> [tcp|udp|tcp-udp] ----
        m = re.match(r"^object-group service (\S+)(?:\s+(tcp|udp|tcp-udp|icmp))?", stripped)
        if m:
            name = m.group(1)
            default_proto = m.group(2) or ""
            svc_members: list[str] = []
            i += 1
            while i < len(lines):
                sub = lines[i]
                if sub and not sub[0].isspace():
                    break
                sub = sub.strip()
                if sub.startswith("service-object "):
                    spec = sub.split(None, 1)[1] if " " in sub else ""
                    svc_members.extend(_parse_service_spec(spec))
                elif sub.startswith("port-object "):
                    spec = sub.split(None, 1)[1] if " " in sub else ""
                    proto = default_proto or "tcp"
                    if proto == "tcp-udp":
                        for p in ("tcp", "udp"):
                            svc_members.extend(_parse_port_spec(p, spec))
                    else:
                        svc_members.extend(_parse_port_spec(proto, spec))
                elif sub.startswith("group-object "):
                    ref = sub.split(None, 1)[1].strip()
                    svc_members.append(f"__svc_grp:{ref}")
                i += 1
            svc_groups[name] = svc_members
            continue

        # ---- object-group icmp-type <name> ----
        m = re.match(r"^object-group icmp-type (\S+)", stripped)
        if m:
            name = m.group(1)
            i += 1
            while i < len(lines):
                sub = lines[i]
                if sub and not sub[0].isspace():
                    break
                i += 1
            svc_groups[name] = ["icmp/any"]
            continue

        i += 1

    # Resolve forward references in groups
    _resolve_net_groups(net_groups, net_objects)
    _resolve_svc_groups(svc_groups, svc_objects)
    return net_objects, svc_objects, net_groups, svc_groups


def _resolve_net_groups(
    net_groups: dict[str, list[str]],
    net_objects: dict[str, list[str]],
    _depth: int = 0,
) -> None:
    """Expand __net_obj: and __net_grp: references in-place."""
    if _depth > 10:
        return
    for name, members in net_groups.items():
        resolved: list[str] = []
        changed = False
        for m in members:
            if m.startswith("__net_obj:"):
                ref = m[len("__net_obj:"):]
                resolved.extend(net_objects.get(ref, [m]))
                changed = True
            elif m.startswith("__net_grp:"):
                ref = m[len("__net_grp:"):]
                resolved.extend(net_groups.get(ref, [m]))
                changed = True
            else:
                resolved.append(m)
        if changed:
            net_groups[name] = resolved


def _resolve_svc_groups(
    svc_groups: dict[str, list[str]],
    svc_objects: dict[str, list[str]],
    _depth: int = 0,
) -> None:
    """Expand __svc_grp: references in-place."""
    if _depth > 10:
        return
    for name, members in svc_groups.items():
        resolved: list[str] = []
        changed = False
        for m in members:
            if m.startswith("__svc_grp:"):
                ref = m[len("__svc_grp:"):]
                resolved.extend(svc_groups.get(ref, [m]))
                changed = True
            else:
                resolved.append(m)
        if changed:
            svc_groups[name] = resolved


# ---------------------------------------------------------------------------
# Service / port spec parsing
# ---------------------------------------------------------------------------

_NAMED_PORTS: dict[str, str] = {
    "ftp": "21", "ssh": "22", "telnet": "23", "smtp": "25",
    "dns": "53", "http": "80", "pop3": "110", "nntp": "119",
    "ntp": "123", "imap4": "143", "snmp": "161", "snmptrap": "162",
    "bgp": "179", "ldap": "389", "https": "443", "smb": "445",
    "syslog": "514", "ldaps": "636", "ftps": "990", "imaps": "993",
    "pop3s": "995", "sqlnet": "1521", "rdp": "3389", "mysql": "3306",
    "mssql": "1433",
}


def _resolve_port(port_str: str) -> str:
    """Resolve named port to number string."""
    return _NAMED_PORTS.get(port_str.lower(), port_str)


def _parse_port_spec(proto: str, spec: str) -> list[str]:
    """Parse 'eq 80', 'range 1024 65535', 'lt 1024', 'gt 1023', 'neq 80' into proto/port strings."""
    parts = spec.strip().split()
    if not parts:
        return [f"{proto}/any"]
    op = parts[0].lower()
    if op == "eq" and len(parts) >= 2:
        return [f"{proto}/{_resolve_port(parts[1])}"]
    if op == "range" and len(parts) >= 3:
        return [f"{proto}/{_resolve_port(parts[1])}-{_resolve_port(parts[2])}"]
    if op in ("lt", "gt", "neq") and len(parts) >= 2:
        return [f"{proto}/{op}:{_resolve_port(parts[1])}"]
    return [f"{proto}/any"]


def _parse_service_spec(spec: str) -> list[str]:
    """
    Parse a service specification like:
      tcp destination eq 80
      tcp source eq 1024 destination eq 80
      udp destination range 100 200
      icmp
      ip
    """
    spec = spec.strip()
    if not spec:
        return ["ALL"]

    parts = spec.split()
    if not parts:
        return ["ALL"]

    proto = parts[0].lower()
    if proto in ("ip", "any"):
        return ["ALL"]
    if proto in ("icmp", "icmpv6", "icmp6"):
        return ["icmp/any"]
    if proto not in ("tcp", "udp", "tcp-udp", "sctp"):
        return [proto]

    # Find destination port spec
    dest_idx = None
    for idx, p in enumerate(parts):
        if p.lower() == "destination" and idx + 1 < len(parts):
            dest_idx = idx + 1
            break
        # Also handle bare eq/range/lt/gt without "destination" keyword
        if p.lower() in ("eq", "range", "lt", "gt", "neq") and idx > 0:
            dest_idx = idx
            break

    if dest_idx is None:
        if proto == "tcp-udp":
            return ["tcp/any", "udp/any"]
        return [f"{proto}/any"]

    port_spec = " ".join(parts[dest_idx:])
    # Remove "destination" prefix if present
    port_spec = re.sub(r"^destination\s+", "", port_spec.strip())

    if proto == "tcp-udp":
        result = []
        result.extend(_parse_port_spec("tcp", port_spec))
        result.extend(_parse_port_spec("udp", port_spec))
        return result
    return _parse_port_spec(proto, port_spec)


# ---------------------------------------------------------------------------
# Address spec parsing in ACL lines
# ---------------------------------------------------------------------------

def _parse_addr_spec(
    tokens: list[str],
    pos: int,
    net_objects: dict[str, list[str]],
    net_groups: dict[str, list[str]],
) -> tuple[list[str], int]:
    """
    Parse an address specifier starting at tokens[pos].

    Returns (list_of_cidrs, new_pos).
    """
    if pos >= len(tokens):
        return ["0.0.0.0/0"], pos

    tok = tokens[pos].lower()

    if tok in ("any", "any4", "any6"):
        return ["0.0.0.0/0"], pos + 1

    if tok == "host":
        if pos + 1 < len(tokens):
            return [f"{tokens[pos + 1]}/32"], pos + 2
        return ["0.0.0.0/0"], pos + 1

    if tok == "object":
        if pos + 1 < len(tokens):
            name = tokens[pos + 1]
            addrs = net_objects.get(name, [name])
            return addrs, pos + 2
        return ["0.0.0.0/0"], pos + 1

    if tok == "object-group":
        if pos + 1 < len(tokens):
            name = tokens[pos + 1]
            addrs = net_groups.get(name, [name])
            return addrs or ["0.0.0.0/0"], pos + 2
        return ["0.0.0.0/0"], pos + 1

    # ip + mask
    if pos + 1 < len(tokens):
        possible_ip = tokens[pos]
        possible_mask = tokens[pos + 1]
        try:
            ipaddress.ip_address(possible_ip)
            # Verify it's a mask (dotted decimal or prefix len)
            if "." in possible_mask or possible_mask.isdigit():
                cidr = _ip_mask_to_cidr(possible_ip, possible_mask)
                return [cidr], pos + 2
        except ValueError:
            pass

    # Fallback: treat as a name reference
    return [tokens[pos]], pos + 1


def _parse_port_tokens(
    proto: str,
    tokens: list[str],
    pos: int,
) -> tuple[list[str], int]:
    """
    Parse optional port spec starting at tokens[pos] for the given proto.
    Returns (services, new_pos).
    """
    if pos >= len(tokens):
        return [], pos

    tok = tokens[pos].lower()
    if tok not in ("eq", "range", "lt", "gt", "neq"):
        return [], pos

    op = tok
    if op == "range":
        if pos + 2 < len(tokens):
            port_spec = f"range {tokens[pos + 1]} {tokens[pos + 2]}"
            return _parse_port_spec(proto, port_spec), pos + 3
        return [], pos
    else:
        if pos + 1 < len(tokens):
            port_spec = f"{op} {tokens[pos + 1]}"
            return _parse_port_spec(proto, port_spec), pos + 2
        return [], pos


# ---------------------------------------------------------------------------
# Interface table
# ---------------------------------------------------------------------------

def _build_interface_table(lines: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """
    Parse interface blocks to build:
      nameif_to_cidr: {nameif → CIDR}
      nameif_to_phys: {physical_intf → nameif}  (for access-group lookup)
    """
    nameif_to_cidr: dict[str, str] = {}
    phys_to_nameif: dict[str, str] = {}

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        m = re.match(r"^interface (\S+)", stripped)
        if m:
            phys_name = m.group(1)
            nameif = None
            ip_cidr = None
            i += 1
            while i < len(lines):
                sub = lines[i]
                if sub and not sub[0].isspace():
                    break
                sub = sub.strip()
                if sub.startswith("nameif "):
                    nameif = sub.split()[1]
                elif sub.startswith("ip address "):
                    parts = sub.split()
                    # ip address <ip> <mask> [standby <ip>]
                    if len(parts) >= 4:
                        try:
                            ipaddress.ip_address(parts[2])
                            ip_cidr = _ip_mask_to_cidr(parts[2], parts[3])
                        except ValueError:
                            pass
                i += 1
            if nameif:
                phys_to_nameif[phys_name] = nameif
                if ip_cidr:
                    nameif_to_cidr[nameif] = ip_cidr
            continue

        i += 1

    return nameif_to_cidr, phys_to_nameif


# ---------------------------------------------------------------------------
# Access-group table
# ---------------------------------------------------------------------------

def _build_acl_interface_map(lines: list[str]) -> dict[str, dict[str, str]]:
    """
    Parse ``access-group <acl> in|out interface <intf>`` lines.

    Returns {acl_name: {"in": intf_name, "out": intf_name}}.
    """
    acl_map: dict[str, dict[str, str]] = {}
    for line in lines:
        stripped = line.strip()
        m = re.match(r"^access-group (\S+) (in|out) interface (\S+)", stripped)
        if m:
            acl_name, direction, intf = m.group(1), m.group(2), m.group(3)
            if acl_name not in acl_map:
                acl_map[acl_name] = {}
            acl_map[acl_name][direction] = intf
    return acl_map


# ---------------------------------------------------------------------------
# ACL parser
# ---------------------------------------------------------------------------

_ACL_REMARK_RE = re.compile(
    r"^access-list (\S+) remark (.*)", re.IGNORECASE
)
_ACL_EXTENDED_RE = re.compile(
    r"^access-list (\S+) (?:line \d+ )?extended (permit|deny) (.*)", re.IGNORECASE
)
_ACL_STANDARD_RE = re.compile(
    r"^access-list (\S+) (?:line \d+ )?standard (permit|deny) (.*)", re.IGNORECASE
)
_ACL_WEBTYPE_RE = re.compile(
    r"^access-list (\S+) (?:line \d+ )?webtype (permit|deny) (.*)", re.IGNORECASE
)


def _parse_acls(
    lines: list[str],
    net_objects: dict[str, list[str]],
    net_groups: dict[str, list[str]],
    svc_objects: dict[str, list[str]],
    svc_groups: dict[str, list[str]],
    acl_intf_map: dict[str, dict[str, str]],
) -> tuple[list[dict], list[str]]:
    """Parse all access-list lines into normalized rules."""
    rules: list[dict] = []
    errors: list[str] = []

    # Collect remarks per ACL to attach to next rule
    pending_remarks: dict[str, list[str]] = {}
    seq_counter: dict[str, int] = {}

    for line in lines:
        stripped = line.strip()

        # Remarks
        m = _ACL_REMARK_RE.match(stripped)
        if m:
            acl_name = m.group(1)
            remark = m.group(2)
            if acl_name not in pending_remarks:
                pending_remarks[acl_name] = []
            pending_remarks[acl_name].append(remark)
            continue

        # Extended ACL
        m = _ACL_EXTENDED_RE.match(stripped)
        if m:
            acl_name = m.group(1)
            action = m.group(2).lower()
            rest = m.group(3)
            try:
                rule = _parse_extended_ace(
                    acl_name, action, rest,
                    net_objects, net_groups, svc_objects, svc_groups, acl_intf_map,
                )
                seq_counter[acl_name] = seq_counter.get(acl_name, 0) + 1
                rule["policy_id"] = f"{acl_name}-{seq_counter[acl_name]}"
                remarks = pending_remarks.pop(acl_name, [])
                rule["comment"] = "; ".join(remarks) if remarks else None
                rules.append(rule)
            except Exception as exc:
                errors.append(f"ACL {acl_name}: {exc} (line: {stripped!r})")
                pending_remarks.pop(acl_name, None)
            continue

        # Standard ACL
        m = _ACL_STANDARD_RE.match(stripped)
        if m:
            acl_name = m.group(1)
            action = m.group(2).lower()
            rest = m.group(3)
            try:
                tokens = rest.split()
                src_addrs, _ = _parse_addr_spec(tokens, 0, net_objects, net_groups)
                intf_info = acl_intf_map.get(acl_name, {})
                src_intf = intf_info.get("in") or intf_info.get("out")
                seq_counter[acl_name] = seq_counter.get(acl_name, 0) + 1
                remarks = pending_remarks.pop(acl_name, [])
                rules.append({
                    "policy_id": f"{acl_name}-{seq_counter[acl_name]}",
                    "name": acl_name,
                    "src_intf": src_intf,
                    "dst_intf": None,
                    "src_addrs": src_addrs,
                    "dst_addrs": ["0.0.0.0/0"],
                    "services": ["ALL"],
                    "action": "deny" if action == "deny" else "permit",
                    "nat": False,
                    "log_traffic": "log" in rest.lower(),
                    "comment": "; ".join(remarks) if remarks else None,
                    "raw": {"acl": acl_name, "type": "standard", "action": action, "rest": rest},
                })
            except Exception as exc:
                errors.append(f"Standard ACL {acl_name}: {exc}")
                pending_remarks.pop(acl_name, None)
            continue

        # Webtype ACL (clientless SSL VPN) — parse minimally
        m = _ACL_WEBTYPE_RE.match(stripped)
        if m:
            acl_name = m.group(1)
            pending_remarks.pop(acl_name, None)
            continue

    return rules, errors


def _parse_extended_ace(
    acl_name: str,
    action: str,
    rest: str,
    net_objects: dict[str, list[str]],
    net_groups: dict[str, list[str]],
    svc_objects: dict[str, list[str]],
    svc_groups: dict[str, list[str]],
    acl_intf_map: dict[str, dict[str, str]],
) -> dict:
    """
    Parse the remainder of an extended ACE after 'permit|deny'.

    Grammar (simplified):
      <proto_spec> <src_addr> [src_port] <dst_addr> [dst_port] [log] [inactive]

    proto_spec:
      ip | tcp | udp | icmp | icmpv6 | ospf | ... |
      object <svc_obj> | object-group <svc_grp>
    """
    tokens = rest.split()
    pos = 0

    # Detect inactive rules
    log_traffic = "log" in [t.lower() for t in tokens]
    inactive = "inactive" in [t.lower() for t in tokens]

    # ---- Protocol / service spec ----
    services: list[str] = []
    proto = "ip"

    if pos < len(tokens) and tokens[pos].lower() == "object":
        # object <svc_obj_name>
        if pos + 1 < len(tokens):
            name = tokens[pos + 1]
            services = svc_objects.get(name, [name])
            pos += 2
            proto = "obj"
    elif pos < len(tokens) and tokens[pos].lower() == "object-group":
        # object-group <svc_grp_name>
        if pos + 1 < len(tokens):
            name = tokens[pos + 1]
            services = svc_groups.get(name, [name])
            pos += 2
            proto = "grp"
    else:
        proto = tokens[pos].lower() if pos < len(tokens) else "ip"
        pos += 1
        if proto in ("ip",):
            services = ["ALL"]
        elif proto in ("icmp", "icmpv6", "icmp6"):
            services = ["icmp/any"]
        elif proto in ("tcp", "udp", "tcp-udp", "sctp"):
            pass  # ports parsed below
        else:
            # Other protocols (ospf, eigrp, gre, etc.)
            services = [proto]

    # ---- Source address ----
    src_addrs, pos = _parse_addr_spec(tokens, pos, net_objects, net_groups)

    # ---- Source port (only for tcp/udp) ----
    if proto in ("tcp", "udp", "tcp-udp", "sctp") and pos < len(tokens) and tokens[pos].lower() in ("eq", "range", "lt", "gt", "neq"):
        # source port – consume but don't track (normalized format doesn't model src ports)
        if tokens[pos].lower() == "range":
            pos += 3
        else:
            pos += 2

    # ---- Destination address ----
    dst_addrs, pos = _parse_addr_spec(tokens, pos, net_objects, net_groups)

    # ---- Destination port ----
    if proto in ("tcp", "udp", "sctp") and not services:
        dst_svcs, pos = _parse_port_tokens(proto, tokens, pos)
        services = dst_svcs or [f"{proto}/any"]
    elif proto == "tcp-udp" and not services:
        dst_svcs_tcp, pos = _parse_port_tokens("tcp", tokens, pos)
        # tcp-udp shares the same port spec; derive udp services from tcp
        dst_svcs_udp = [s.replace("tcp/", "udp/") for s in dst_svcs_tcp]
        services = (dst_svcs_tcp or ["tcp/any"]) + (dst_svcs_udp or ["udp/any"])

    if not services:
        services = ["ALL"]

    # ---- Interface from access-group map ----
    intf_info = acl_intf_map.get(acl_name, {})
    src_intf = intf_info.get("in") or intf_info.get("out")
    dst_intf = None
    # If the ACL is applied "out" on an interface, it controls egress
    if "out" in intf_info and "in" not in intf_info:
        dst_intf = intf_info["out"]
        src_intf = None

    return {
        "policy_id": "",  # set by caller
        "name": acl_name,
        "src_intf": src_intf,
        "dst_intf": dst_intf,
        "src_addrs": src_addrs,
        "dst_addrs": dst_addrs,
        "services": services,
        "action": "deny" if action == "deny" else "permit",
        "nat": False,
        "log_traffic": log_traffic,
        "comment": None,  # set by caller
        "raw": {
            "acl": acl_name,
            "type": "extended",
            "action": action,
            "proto": proto,
            "inactive": inactive,
            "rest": rest,
        },
    }


# ---------------------------------------------------------------------------
# NAT rules
# ---------------------------------------------------------------------------

def _parse_nat_rules(lines: list[str]) -> list[dict]:
    """
    Parse ``nat`` statements into minimal normalized rule dicts.

    Handles both:
      - ASA 8.3+ object NAT:  ``nat (real_ifc,mapped_ifc) ...`` under object block
      - Twice NAT:            ``nat (real,mapped) ... source static ... destination static ...``
    """
    nat_rules: list[dict] = []
    seq = 0

    # Twice NAT / global NAT lines (top-level nat statements)
    nat_re = re.compile(
        r"^nat\s+\(([^)]+)\)\s+(\d+)?\s*(static|dynamic|dynamic-nat|pat)\s+(.*)",
        re.IGNORECASE,
    )
    nat_re2 = re.compile(
        r"^nat\s+\(([^)]+)\)\s+(source)\s+(.*)",
        re.IGNORECASE,
    )

    # Object-based NAT is parsed during object parsing; here we only grab top-level
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("nat "):
            continue

        m = nat_re.match(stripped) or nat_re2.match(stripped)
        if m:
            seq += 1
            ifc_pair = m.group(1)
            parts = ifc_pair.split(",")
            src_intf = parts[0].strip() if parts else None
            dst_intf = parts[1].strip() if len(parts) > 1 else None
            nat_rules.append({
                "policy_id": f"nat-{seq}",
                "name": None,
                "src_intf": src_intf,
                "dst_intf": dst_intf,
                "src_addrs": ["0.0.0.0/0"],
                "dst_addrs": ["0.0.0.0/0"],
                "services": ["ALL"],
                "action": "permit",
                "nat": True,
                "log_traffic": False,
                "comment": stripped[:120],
                "raw": {"type": "nat", "line": stripped},
            })

    return nat_rules


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_cisco_asa(text: str) -> dict:
    """
    Parse a Cisco ASA firewall config.

    Accepts ``show running-config`` / ``write terminal`` output.

    Returns:
      {
        "rules": list[dict],          # normalized rules
        "interfaces": dict,           # nameif → CIDR
        "addresses": dict,            # raw object table
        "parse_errors": list[str],
      }
    """
    lines = text.splitlines()

    # Build object/group tables
    net_objects, svc_objects, net_groups, svc_groups = _build_object_tables(lines)

    # Build interface table
    nameif_to_cidr, _ = _build_interface_table(lines)

    # Build access-group → interface map
    acl_intf_map = _build_acl_interface_map(lines)

    # Parse ACLs
    rules, errors = _parse_acls(
        lines, net_objects, net_groups, svc_objects, svc_groups, acl_intf_map
    )

    # Parse NAT rules
    nat_rules = _parse_nat_rules(lines)
    rules.extend(nat_rules)

    # Re-number policy_ids
    for i, rule in enumerate(rules):
        if not rule.get("policy_id"):
            rule["policy_id"] = str(i + 1)

    # Flatten address objects into the addresses dict
    addresses: dict[str, Any] = {}
    for name, addrs in net_objects.items():
        addresses[name] = {"type": "network", "cidrs": addrs}

    if not rules and not errors:
        errors.append("No access-list rules found in config")

    return {
        "rules": rules,
        "interfaces": nameif_to_cidr,
        "addresses": addresses,
        "parse_errors": errors,
    }
