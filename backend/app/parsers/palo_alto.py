"""
Palo Alto Networks PAN-OS firewall config parser.

Handles the XML config format produced by:
  - ``scp export configuration`` from PAN-OS CLI
  - Panorama ``Export Device Configuration`` or ``Export Shared Policy``
  - ``show config running`` XML output

Also handles PAN-OS ``set`` format (CLI set commands).

Returns the same normalized rule dict format as the Fortinet parser:
  {
    "policy_id": str,
    "name": str | None,
    "src_intf": str | None,   # zone name (from-zone)
    "dst_intf": str | None,   # zone name (to-zone)
    "src_addrs": list[str],   # CIDR strings or "0.0.0.0/0"
    "dst_addrs": list[str],
    "services": list[str],    # "proto/port" or "ALL"
    "action": "permit" | "deny",
    "nat": bool,
    "log_traffic": bool,
    "comment": str | None,
    "raw": dict,
  }

Also returns the address object table, address group table, and interface table.
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from typing import Any


# ---------------------------------------------------------------------------
# Built-in service resolution
# ---------------------------------------------------------------------------

_BUILTIN_SERVICES: dict[str, list[str]] = {
    "any": ["ALL"],
    "application-default": ["ALL"],
    "service-http": ["tcp/80"],
    "service-https": ["tcp/443"],
}

_PROTO_PORT_RE = re.compile(r"^(tcp|udp|icmp)/", re.IGNORECASE)


def _resolve_service(
    name: str,
    svc_table: dict[str, Any],
    svcgrp_table: dict[str, Any],
    _depth: int = 0,
) -> list[str]:
    """Resolve a PAN-OS service name to list of 'proto/port' strings."""
    if _depth > 10:
        return [name]
    lower = name.lower()
    if lower in _BUILTIN_SERVICES:
        return _BUILTIN_SERVICES[lower]

    # Service group
    if name in svcgrp_table:
        members = svcgrp_table[name]
        result: list[str] = []
        for m in members:
            result.extend(_resolve_service(m, svc_table, svcgrp_table, _depth + 1))
        return result or [name]

    # Custom service object
    if name in svc_table:
        obj = svc_table[name]
        proto = obj.get("protocol", "tcp").lower()
        port = obj.get("port", "")
        if port:
            # Port can be a range like "8080-8090"; keep as-is
            return [f"{proto}/{port}"]
        return [f"{proto}/0"]

    # If it already looks like proto/port leave it
    if _PROTO_PORT_RE.match(name):
        return [name]

    return [name.lower()]


# ---------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------

def _resolve_address(
    name: str,
    addr_table: dict[str, Any],
    addrgrp_table: dict[str, Any],
    _depth: int = 0,
) -> list[str]:
    """Resolve a PAN-OS address name to a list of CIDR strings."""
    if _depth > 10:
        return [name]
    if name.lower() in ("any", "any-ipv4", "any-ipv6"):
        return ["0.0.0.0/0"]

    # Try direct CIDR
    try:
        ipaddress.ip_network(name, strict=False)
        return [name]
    except ValueError:
        pass

    # Address group
    if name in addrgrp_table:
        members = addrgrp_table[name]
        result: list[str] = []
        for m in members:
            result.extend(_resolve_address(m, addr_table, addrgrp_table, _depth + 1))
        return result or [name]

    # Address object
    if name in addr_table:
        obj = addr_table[name]
        obj_type = obj.get("type", "ip-netmask")
        value = obj.get("value", "")
        if obj_type == "ip-netmask" and value:
            try:
                net = ipaddress.ip_network(value, strict=False)
                return [str(net)]
            except ValueError:
                return [value]
        if obj_type == "ip-range" and value:
            return [f"range:{value}"]
        if obj_type == "fqdn" and value:
            return [f"fqdn:{value}"]
        if value:
            return [value]

    return [name]


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _members(element: ET.Element | None, tag: str = "member") -> list[str]:
    """Extract text values from child <member> elements."""
    if element is None:
        return []
    return [m.text.strip() for m in element.findall(tag) if m.text]


def _text(element: ET.Element | None, path: str, default: str = "") -> str:
    """Safely get text from a sub-element path."""
    if element is None:
        return default
    el = element.find(path)
    if el is None or el.text is None:
        return default
    return el.text.strip()


def _build_address_table(vsys_el: ET.Element) -> dict[str, Any]:
    """Build {name: {type, value}} from vsys <address> block."""
    table: dict[str, Any] = {}
    for entry in vsys_el.findall("./address/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        obj: dict[str, Any] = {}
        for tag in ("ip-netmask", "ip-range", "fqdn"):
            el = entry.find(tag)
            if el is not None and el.text:
                obj["type"] = tag
                obj["value"] = el.text.strip()
                break
        table[name] = obj
    return table


def _build_addrgrp_table(vsys_el: ET.Element) -> dict[str, list[str]]:
    """Build {name: [member, ...]} from vsys <address-group> block."""
    table: dict[str, list[str]] = {}
    for entry in vsys_el.findall("./address-group/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        members = _members(entry.find("static"))
        table[name] = members
    return table


def _build_service_table(vsys_el: ET.Element) -> dict[str, Any]:
    """Build {name: {protocol, port}} from vsys <service> block."""
    table: dict[str, Any] = {}
    for entry in vsys_el.findall("./service/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        proto_el = entry.find("protocol")
        if proto_el is None:
            continue
        for proto in ("tcp", "udp", "icmp", "icmp6", "sctp"):
            p_el = proto_el.find(proto)
            if p_el is not None:
                port = _text(p_el, "port", "")
                table[name] = {"protocol": proto, "port": port}
                break
    return table


def _build_svcgrp_table(vsys_el: ET.Element) -> dict[str, list[str]]:
    """Build {name: [member, ...]} from vsys <service-group> block."""
    table: dict[str, list[str]] = {}
    for entry in vsys_el.findall("./service-group/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        table[name] = _members(entry.find("members"))
    return table


def _build_interface_table(root: ET.Element) -> dict[str, str]:
    """
    Return {interface_name: ip_cidr} from network interface config.
    Handles ethernet, loopback, tunnel, vlan, and aggregate interfaces.
    """
    intf_table: dict[str, str] = {}
    # Handles both full device config and exported configs
    for intf_parent in root.findall(".//interface"):
        for intf_type_el in list(intf_parent):
            for intf_entry in intf_type_el.findall("entry"):
                name = intf_entry.get("name", "")
                if not name:
                    continue
                # Layer3 interface with IP
                ip_el = intf_entry.find(".//layer3/ip/entry")
                if ip_el is not None:
                    ip_val = ip_el.get("name", "")
                    if ip_val:
                        try:
                            net = ipaddress.ip_network(ip_val, strict=False)
                            intf_table[name] = str(net)
                        except ValueError:
                            intf_table[name] = ip_val
                # Directly assigned IP
                ip_el2 = intf_entry.find("ip/entry")
                if ip_el2 is not None and name not in intf_table:
                    ip_val = ip_el2.get("name", "")
                    if ip_val:
                        try:
                            net = ipaddress.ip_network(ip_val, strict=False)
                            intf_table[name] = str(net)
                        except ValueError:
                            intf_table[name] = ip_val
    return intf_table


def _parse_security_rules(
    rules_el: ET.Element,
    addr_table: dict[str, Any],
    addrgrp_table: dict[str, list[str]],
    svc_table: dict[str, Any],
    svcgrp_table: dict[str, list[str]],
) -> tuple[list[dict], list[str]]:
    """Parse <security><rules> entries into normalized rule dicts."""
    rules: list[dict] = []
    errors: list[str] = []
    seq = 0

    for entry in rules_el.findall("entry"):
        name = entry.get("name", "")
        seq += 1
        try:
            # Zones
            from_zones = _members(entry.find("from"))
            to_zones = _members(entry.find("to"))
            src_intf = from_zones[0] if len(from_zones) == 1 else (", ".join(from_zones) if from_zones else None)
            dst_intf = to_zones[0] if len(to_zones) == 1 else (", ".join(to_zones) if to_zones else None)

            # Source / destination addresses
            src_names = _members(entry.find("source"))
            dst_names = _members(entry.find("destination"))

            src_addrs: list[str] = []
            for sn in src_names:
                src_addrs.extend(_resolve_address(sn, addr_table, addrgrp_table))
            if not src_addrs:
                src_addrs = ["0.0.0.0/0"]

            dst_addrs: list[str] = []
            for dn in dst_names:
                dst_addrs.extend(_resolve_address(dn, addr_table, addrgrp_table))
            if not dst_addrs:
                dst_addrs = ["0.0.0.0/0"]

            # Services
            svc_names = _members(entry.find("service"))
            services: list[str] = []
            for sv in svc_names:
                services.extend(_resolve_service(sv, svc_table, svcgrp_table))
            if not services:
                services = ["ALL"]

            # Action
            action_raw = _text(entry, "action", "allow").lower()
            action = "deny" if action_raw in ("deny", "drop", "reset-client", "reset-server", "reset-both") else "permit"

            # Logging
            log_start = _text(entry, "log-start", "no").lower()
            log_end = _text(entry, "log-end", "yes").lower()
            log_traffic = log_end == "yes" or log_start == "yes"

            # Description / comment
            description = _text(entry, "description", None)

            raw_dict = {
                "name": name,
                "from_zones": from_zones,
                "to_zones": to_zones,
                "source": src_names,
                "destination": dst_names,
                "service": svc_names,
                "action": action_raw,
            }

            # Disabled rules
            disabled = _text(entry, "disabled", "no").lower()
            if disabled == "yes":
                raw_dict["disabled"] = True

            rules.append({
                "policy_id": str(seq),
                "name": name or None,
                "src_intf": src_intf,
                "dst_intf": dst_intf,
                "src_addrs": src_addrs,
                "dst_addrs": dst_addrs,
                "services": services,
                "action": action,
                "nat": False,  # Security rules don't NAT; NAT rules are separate
                "log_traffic": log_traffic,
                "comment": description or None,
                "raw": raw_dict,
            })
        except Exception as exc:
            errors.append(f"Rule {name!r} (seq {seq}): {exc}")

    return rules, errors


def _parse_nat_rules(
    rules_el: ET.Element,
    addr_table: dict[str, Any],
    addrgrp_table: dict[str, list[str]],
    svc_table: dict[str, Any],
    svcgrp_table: dict[str, list[str]],
    seq_offset: int,
) -> tuple[list[dict], list[str]]:
    """Parse <nat><rules> entries into normalized rule dicts (action=permit, nat=True)."""
    rules: list[dict] = []
    errors: list[str] = []
    seq = seq_offset

    for entry in rules_el.findall("entry"):
        name = entry.get("name", "")
        seq += 1
        try:
            from_zones = _members(entry.find("from"))
            to_zones = _members(entry.find("to"))
            src_intf = from_zones[0] if len(from_zones) == 1 else (", ".join(from_zones) if from_zones else None)
            dst_intf = to_zones[0] if len(to_zones) == 1 else (", ".join(to_zones) if to_zones else None)

            src_names = _members(entry.find("source"))
            dst_names = _members(entry.find("destination"))

            src_addrs: list[str] = []
            for sn in src_names:
                src_addrs.extend(_resolve_address(sn, addr_table, addrgrp_table))
            if not src_addrs:
                src_addrs = ["0.0.0.0/0"]

            dst_addrs: list[str] = []
            for dn in dst_names:
                dst_addrs.extend(_resolve_address(dn, addr_table, addrgrp_table))
            if not dst_addrs:
                dst_addrs = ["0.0.0.0/0"]

            svc_names = _members(entry.find("service"))
            services: list[str] = []
            for sv in svc_names:
                services.extend(_resolve_service(sv, svc_table, svcgrp_table))
            if not services:
                services = ["ALL"]

            description = _text(entry, "description", None)

            rules.append({
                "policy_id": f"nat-{seq}",
                "name": name or None,
                "src_intf": src_intf,
                "dst_intf": dst_intf,
                "src_addrs": src_addrs,
                "dst_addrs": dst_addrs,
                "services": services,
                "action": "permit",
                "nat": True,
                "log_traffic": False,
                "comment": description or None,
                "raw": {
                    "name": name,
                    "type": "nat",
                    "from_zones": from_zones,
                    "to_zones": to_zones,
                    "source": src_names,
                    "destination": dst_names,
                    "service": svc_names,
                },
            })
        except Exception as exc:
            errors.append(f"NAT rule {name!r} (seq {seq}): {exc}")

    return rules, errors


def _parse_vsys(
    vsys_el: ET.Element,
    root: ET.Element,
) -> tuple[list[dict], dict[str, str], dict[str, Any], list[str]]:
    """
    Parse a single vsys element and return (rules, interfaces, addresses, errors).
    """
    addr_table = _build_address_table(vsys_el)
    addrgrp_table = _build_addrgrp_table(vsys_el)
    svc_table = _build_service_table(vsys_el)
    svcgrp_table = _build_svcgrp_table(vsys_el)
    interface_table = _build_interface_table(root)

    all_rules: list[dict] = []
    all_errors: list[str] = []

    # Security policy rules
    sec_rules_el = vsys_el.find("./rulebase/security/rules")
    if sec_rules_el is not None:
        rules, errors = _parse_security_rules(
            sec_rules_el, addr_table, addrgrp_table, svc_table, svcgrp_table
        )
        all_rules.extend(rules)
        all_errors.extend(errors)

    # NAT policy rules
    nat_rules_el = vsys_el.find("./rulebase/nat/rules")
    if nat_rules_el is not None:
        rules, errors = _parse_nat_rules(
            nat_rules_el, addr_table, addrgrp_table, svc_table, svcgrp_table,
            seq_offset=len(all_rules),
        )
        all_rules.extend(rules)
        all_errors.extend(errors)

    # Pre-rulebase (Panorama shared/device-group policies)
    for rulebase_path in ("./pre-rulebase/security/rules", "./post-rulebase/security/rules"):
        pre_rules_el = vsys_el.find(rulebase_path)
        if pre_rules_el is not None:
            rules, errors = _parse_security_rules(
                pre_rules_el, addr_table, addrgrp_table, svc_table, svcgrp_table
            )
            all_rules.extend(rules)
            all_errors.extend(errors)

    return all_rules, interface_table, addr_table, all_errors


# ---------------------------------------------------------------------------
# Set-format fallback parser
# ---------------------------------------------------------------------------

_SET_SECURITY_RE = re.compile(
    r"set security policies from-zone (\S+) to-zone (\S+) policy (\S+) "
    r"(?:match (source|destination|application|service)|then (\S+))",
    re.IGNORECASE,
)


def _parse_set_format(text: str) -> dict:
    """
    Minimal parser for PAN-OS ``set`` CLI format.
    Extracts security policy entries only.
    """
    rules: list[dict] = []
    errors: list[str] = []
    policies: dict[str, dict] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("set security policies"):
            continue
        parts = line.split()
        # set security policies from-zone <FZ> to-zone <TZ> policy <NAME> match source <S>
        if len(parts) < 9:
            continue
        try:
            idx_from = parts.index("from-zone")
            idx_to = parts.index("to-zone")
            idx_policy = parts.index("policy")
        except ValueError:
            continue
        fz = parts[idx_from + 1]
        tz = parts[idx_to + 1]
        policy_name = parts[idx_policy + 1]

        key = f"{fz}|{tz}|{policy_name}"
        if key not in policies:
            policies[key] = {
                "from_zone": fz,
                "to_zone": tz,
                "name": policy_name,
                "sources": [],
                "destinations": [],
                "services": [],
                "action": "permit",
            }

        if "match" in parts:
            idx_match = parts.index("match")
            if idx_match + 2 < len(parts):
                match_key = parts[idx_match + 1]
                match_val = parts[idx_match + 2]
                if match_key == "source":
                    policies[key]["sources"].append(match_val)
                elif match_key == "destination":
                    policies[key]["destinations"].append(match_val)
                elif match_key == "service":
                    policies[key]["services"].append(match_val)
        elif "then" in parts:
            idx_then = parts.index("then")
            if idx_then + 1 < len(parts):
                action_val = parts[idx_then + 1].lower()
                policies[key]["action"] = "deny" if action_val in ("deny", "reject") else "permit"

    seq = 0
    for pol in policies.values():
        seq += 1
        src_addrs = [s if s.lower() != "any" else "0.0.0.0/0" for s in pol["sources"]] or ["0.0.0.0/0"]
        dst_addrs = [d if d.lower() != "any" else "0.0.0.0/0" for d in pol["destinations"]] or ["0.0.0.0/0"]
        svc_list = pol["services"] or ["ALL"]

        rules.append({
            "policy_id": str(seq),
            "name": pol["name"],
            "src_intf": pol["from_zone"],
            "dst_intf": pol["to_zone"],
            "src_addrs": src_addrs,
            "dst_addrs": dst_addrs,
            "services": svc_list,
            "action": pol["action"],
            "nat": False,
            "log_traffic": False,
            "comment": None,
            "raw": pol,
        })

    return {
        "rules": rules,
        "interfaces": {},
        "addresses": {},
        "parse_errors": errors,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_palo_alto(text: str) -> dict:
    """
    Parse a Palo Alto Networks PAN-OS firewall config.

    Accepts:
      - Full device XML config (from ``scp export configuration`` or ``show config running``)
      - Exported policy XML (Panorama device-group or shared policy export)
      - PAN-OS ``set`` format CLI output (fallback)

    Returns:
      {
        "rules": list[dict],          # normalized rules
        "interfaces": dict,           # name → CIDR
        "addresses": dict,            # raw address objects
        "parse_errors": list[str],
      }
    """
    stripped = text.strip()

    # Detect set format (no XML)
    if not stripped.startswith("<"):
        if "set security policies" in stripped:
            return _parse_set_format(text)
        # Unknown text format — return empty
        return {"rules": [], "interfaces": {}, "addresses": {}, "parse_errors": ["Unrecognized Palo Alto config format"]}

    # XML format
    try:
        root = ET.fromstring(stripped)
    except ET.ParseError as exc:
        return {"rules": [], "interfaces": {}, "addresses": {}, "parse_errors": [f"XML parse error: {exc}"]}

    all_rules: list[dict] = []
    all_interfaces: dict[str, str] = {}
    all_addresses: dict[str, Any] = {}
    all_errors: list[str] = []

    # Normalize: handle both <config> root and a direct <devices> or <vsys> root
    # Try multiple vsys location patterns
    vsys_entries: list[tuple[ET.Element, ET.Element]] = []  # (vsys_el, config_root)

    config_root = root if root.tag == "config" else root

    # Full config: config/devices/entry/vsys/entry
    for vsys_el in config_root.findall(".//vsys/entry"):
        vsys_entries.append((vsys_el, config_root))

    # Panorama device-group policies under config/devices/entry/device-group/entry
    for dg_el in config_root.findall(".//device-group/entry"):
        vsys_entries.append((dg_el, config_root))

    # If nothing found, treat root as vsys directly (exported partial config)
    if not vsys_entries:
        vsys_entries.append((config_root, config_root))

    for vsys_el, cfg_root in vsys_entries:
        rules, interfaces, addresses, errors = _parse_vsys(vsys_el, cfg_root)
        all_rules.extend(rules)
        all_interfaces.update(interfaces)
        all_addresses.update(addresses)
        all_errors.extend(errors)

    # Deduplicate rules by policy_id collision across vsys (re-number)
    for i, rule in enumerate(all_rules):
        rule["policy_id"] = str(i + 1)

    return {
        "rules": all_rules,
        "interfaces": all_interfaces,
        "addresses": {k: v for k, v in all_addresses.items() if isinstance(v, dict)},
        "parse_errors": all_errors,
    }
