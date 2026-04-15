"""Firewall config parsers. Each parser returns a list of normalized rule dicts."""
from .fortinet import parse_fortinet
from .iptables import parse_iptables

__all__ = ["parse_fortinet", "parse_iptables"]
