"""Firewall config parsers. Each parser returns a list of normalized rule dicts."""
from .cisco_asa import parse_cisco_asa
from .fortinet import parse_fortinet
from .iptables import parse_iptables
from .palo_alto import parse_palo_alto

__all__ = ["parse_cisco_asa", "parse_fortinet", "parse_iptables", "parse_palo_alto"]
