"""
iptables-save / iptables -L -n output parser.

Handles the `-A CHAIN -s src -d dst -p proto --dport port -j ACTION` format.
Returns the same normalized rule dict format as the Fortinet parser.
"""

from __future__ import annotations

import re
from typing import Optional


_LINE_RE = re.compile(
    r"-A\s+(\S+)"           # chain
    r"(?:\s+-s\s+(\S+))?"   # source
    r"(?:\s+-d\s+(\S+))?"   # destination
    r"(?:\s+-i\s+(\S+))?"   # in-interface
    r"(?:\s+-o\s+(\S+))?"   # out-interface
    r"(?:.*?-p\s+(\S+))?"   # protocol
    r"(?:.*?--dport\s+(\S+))?"  # dest port
    r"(?:.*?--sport\s+(\S+))?"  # src port
    r"(?:.*?-m\s+\S+)*"     # modules (skip)
    r".*?-j\s+(\S+)",       # jump / action
    re.IGNORECASE,
)


def _normalise_cidr(addr: Optional[str]) -> str:
    if not addr or addr in ("0.0.0.0/0", "anywhere"):
        return "0.0.0.0/0"
    # iptables sometimes writes 10.0.0.0/255.255.255.0 style
    if "/" in addr:
        ip, mask = addr.split("/", 1)
        if "." in mask:
            try:
                prefix = sum(bin(int(x)).count("1") for x in mask.split("."))
                return f"{ip}/{prefix}"
            except Exception:
                pass
    return addr


def parse_iptables(text: str) -> dict:
    """
    Parse iptables-save output.

    Returns same structure as parse_fortinet:
      { "rules": [...], "interfaces": {}, "addresses": {}, "parse_errors": [...] }
    """
    rules = []
    errors = []
    seq = 0

    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("*") or line.startswith(":"):
            continue
        if not line.startswith("-A"):
            continue

        m = _LINE_RE.search(line)
        if not m:
            errors.append(f"Line {line_no}: could not parse: {line[:80]}")
            continue

        chain, src, dst, in_intf, out_intf, proto, dport, sport, target = m.groups()

        action_raw = (target or "").upper()
        action = "permit" if action_raw in ("ACCEPT", "RETURN") else "deny"

        src_cidr = _normalise_cidr(src)
        dst_cidr = _normalise_cidr(dst)

        if proto and dport:
            services = [f"{proto.lower()}/{dport}"]
        elif proto and proto.lower() not in ("all", "tcp", "udp"):
            services = [f"{proto.lower()}/0"]
        else:
            services = ["ALL"]

        seq += 1
        rules.append({
            "policy_id": str(seq),
            "name": f"{chain}/{seq}",
            "src_intf": in_intf,
            "dst_intf": out_intf,
            "src_addrs": [src_cidr],
            "dst_addrs": [dst_cidr],
            "services": services,
            "action": action,
            "nat": chain.upper() in ("PREROUTING", "POSTROUTING", "OUTPUT"),
            "log_traffic": False,
            "comment": None,
            "raw": {"chain": chain, "raw": line},
        })

    return {
        "rules": rules,
        "interfaces": {},
        "addresses": {},
        "parse_errors": errors,
    }
