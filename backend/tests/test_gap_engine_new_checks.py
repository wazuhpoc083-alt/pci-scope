"""
Tests for the 5 new PCI DSS gap checks added in MOU-21.

Run with:  pytest tests/test_gap_engine_new_checks.py -v

New checks covered:
  GAP-INSECURE-PROTO   (Req 1.2.6)
  GAP-BROAD-INTERNAL-CDE (Req 1.3.1)
  GAP-SPOOF            (Req 1.4.3)
  GAP-CDE-NO-NAT       (Req 1.4.5)
  GAP-WIRELESS-CDE     (Req 1.3.3)
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.gap_engine import run_gap_analysis


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _rule(
    policy_id: str = "1",
    src_addrs: list[str] | None = None,
    dst_addrs: list[str] | None = None,
    services: list[str] | None = None,
    action: str = "permit",
    src_intf: str | None = None,
    dst_intf: str | None = None,
    nat: bool = True,
    comment: str | None = "business justification",
) -> dict:
    return {
        "policy_id": policy_id,
        "src_addrs": src_addrs or ["192.168.1.0/24"],
        "dst_addrs": dst_addrs or ["10.0.0.1"],
        "services": services or ["tcp/443"],
        "action": action,
        "src_intf": src_intf,
        "dst_intf": dst_intf,
        "nat": nat,
        "log_traffic": True,
        "comment": comment,
    }


def _gap_ids(rules, cde_seeds=None, **kwargs):
    result = run_gap_analysis(rules, cde_seeds or [], [], **kwargs)
    return {f["id"] for f in result["gap_findings"]}


# ---------------------------------------------------------------------------
# GAP-INSECURE-PROTO (Req 1.2.6)
# ---------------------------------------------------------------------------

class TestInsecureProtocols:
    def test_telnet_port_triggers(self):
        rules = [_rule(services=["tcp/23"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_ftp_control_port_triggers(self):
        rules = [_rule(services=["tcp/21"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_ftp_data_port_triggers(self):
        rules = [_rule(services=["tcp/20"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_tftp_port_triggers(self):
        rules = [_rule(services=["udp/69"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_rsh_port_triggers(self):
        rules = [_rule(services=["tcp/514"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_rlogin_port_triggers(self):
        rules = [_rule(services=["tcp/513"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_service_name_telnet_triggers(self):
        rules = [_rule(services=["TELNET"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_service_name_ftp_triggers(self):
        rules = [_rule(services=["ftp"])]
        assert "GAP-INSECURE-PROTO" in _gap_ids(rules)

    def test_https_does_not_trigger(self):
        rules = [_rule(services=["tcp/443"])]
        assert "GAP-INSECURE-PROTO" not in _gap_ids(rules)

    def test_ssh_does_not_trigger(self):
        rules = [_rule(services=["tcp/22"])]
        assert "GAP-INSECURE-PROTO" not in _gap_ids(rules)

    def test_deny_rule_does_not_trigger(self):
        rules = [_rule(services=["tcp/23"], action="deny")]
        assert "GAP-INSECURE-PROTO" not in _gap_ids(rules)

    def test_finding_lists_affected_rule(self):
        rules = [_rule(policy_id="42", services=["tcp/23"])]
        result = run_gap_analysis(rules, [], [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-INSECURE-PROTO")
        assert "42" in finding["affected_rules"]

    def test_severity_is_high(self):
        rules = [_rule(services=["tcp/23"])]
        result = run_gap_analysis(rules, [], [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-INSECURE-PROTO")
        assert finding["severity"] == "high"

    def test_requirement_tag(self):
        rules = [_rule(services=["tcp/23"])]
        result = run_gap_analysis(rules, [], [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-INSECURE-PROTO")
        assert "1.2.6" in finding["requirement"]


# ---------------------------------------------------------------------------
# GAP-BROAD-INTERNAL-CDE (Req 1.3.1)
# ---------------------------------------------------------------------------

class TestBroadInternalCde:
    _CDE = ["10.5.0.0/24"]

    def test_private_source_all_services_to_cde_triggers(self):
        rules = [_rule(src_addrs=["192.168.1.0/24"], dst_addrs=["10.5.0.1"], services=["ALL"])]
        assert "GAP-BROAD-INTERNAL-CDE" in _gap_ids(rules, self._CDE)

    def test_any_source_all_services_to_cde_triggers(self):
        rules = [_rule(src_addrs=["any"], dst_addrs=["10.5.0.0/24"], services=["ANY"])]
        assert "GAP-BROAD-INTERNAL-CDE" in _gap_ids(rules, self._CDE)

    def test_specific_port_to_cde_does_not_trigger(self):
        rules = [_rule(src_addrs=["192.168.1.0/24"], dst_addrs=["10.5.0.1"], services=["tcp/443"])]
        assert "GAP-BROAD-INTERNAL-CDE" not in _gap_ids(rules, self._CDE)

    def test_no_cde_seeds_no_finding(self):
        rules = [_rule(src_addrs=["192.168.1.0/24"], dst_addrs=["10.5.0.1"], services=["ALL"])]
        assert "GAP-BROAD-INTERNAL-CDE" not in _gap_ids(rules, [])

    def test_internet_source_to_cde_not_counted(self):
        """Internet→CDE is caught by GAP-INET-TO-CDE, not this check."""
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], services=["ALL"])]
        # GAP-INET-TO-CDE may fire but GAP-BROAD-INTERNAL-CDE should not
        assert "GAP-BROAD-INTERNAL-CDE" not in _gap_ids(rules, self._CDE)

    def test_deny_rule_does_not_trigger(self):
        rules = [_rule(src_addrs=["192.168.0.0/16"], dst_addrs=["10.5.0.1"], services=["ALL"], action="deny")]
        assert "GAP-BROAD-INTERNAL-CDE" not in _gap_ids(rules, self._CDE)

    def test_severity_is_medium(self):
        rules = [_rule(src_addrs=["192.168.1.0/24"], dst_addrs=["10.5.0.1"], services=["ALL"])]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next((f for f in result["gap_findings"] if f["id"] == "GAP-BROAD-INTERNAL-CDE"), None)
        assert finding is not None
        assert finding["severity"] == "medium"

    def test_requirement_tag(self):
        rules = [_rule(src_addrs=["192.168.1.0/24"], dst_addrs=["10.5.0.1"], services=["ALL"])]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-BROAD-INTERNAL-CDE")
        assert "1.3.1" in finding["requirement"]


# ---------------------------------------------------------------------------
# GAP-SPOOF (Req 1.4.3)
# ---------------------------------------------------------------------------

class TestAntiSpoofing:
    def test_private_src_from_wan_interface_triggers(self):
        rules = [_rule(src_addrs=["10.0.0.0/8"], src_intf="wan1")]
        assert "GAP-SPOOF" in _gap_ids(rules)

    def test_private_src_from_untrust_triggers(self):
        rules = [_rule(src_addrs=["172.16.0.0/12"], src_intf="untrust")]
        assert "GAP-SPOOF" in _gap_ids(rules)

    def test_private_src_from_external_triggers(self):
        rules = [_rule(src_addrs=["192.168.0.0/16"], src_intf="external")]
        assert "GAP-SPOOF" in _gap_ids(rules)

    def test_private_src_from_internet_triggers(self):
        rules = [_rule(src_addrs=["10.1.2.3/32"], src_intf="internet")]
        assert "GAP-SPOOF" in _gap_ids(rules)

    def test_private_src_from_internal_interface_no_trigger(self):
        rules = [_rule(src_addrs=["192.168.1.0/24"], src_intf="lan")]
        assert "GAP-SPOOF" not in _gap_ids(rules)

    def test_public_src_from_wan_no_trigger(self):
        rules = [_rule(src_addrs=["1.2.3.4"], src_intf="wan1")]
        assert "GAP-SPOOF" not in _gap_ids(rules)

    def test_no_src_intf_no_trigger(self):
        rules = [_rule(src_addrs=["10.0.0.0/8"], src_intf=None)]
        assert "GAP-SPOOF" not in _gap_ids(rules)

    def test_deny_rule_does_not_trigger(self):
        rules = [_rule(src_addrs=["10.0.0.0/8"], src_intf="wan1", action="deny")]
        assert "GAP-SPOOF" not in _gap_ids(rules)

    def test_severity_is_high(self):
        rules = [_rule(src_addrs=["10.0.0.0/8"], src_intf="wan1")]
        result = run_gap_analysis(rules, [], [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-SPOOF")
        assert finding["severity"] == "high"

    def test_requirement_tag(self):
        rules = [_rule(src_addrs=["10.0.0.0/8"], src_intf="wan1")]
        result = run_gap_analysis(rules, [], [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-SPOOF")
        assert "1.4.3" in finding["requirement"]


# ---------------------------------------------------------------------------
# GAP-CDE-NO-NAT (Req 1.4.5)
# ---------------------------------------------------------------------------

class TestCdeNoNat:
    _CDE = ["10.5.0.0/24"]

    def test_internet_to_cde_no_nat_triggers(self):
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], nat=False)]
        assert "GAP-CDE-NO-NAT" in _gap_ids(rules, self._CDE)

    def test_internet_to_cde_with_nat_no_trigger(self):
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], nat=True)]
        assert "GAP-CDE-NO-NAT" not in _gap_ids(rules, self._CDE)

    def test_internal_to_cde_no_nat_no_trigger(self):
        """Only internet→CDE without NAT is flagged."""
        rules = [_rule(src_addrs=["192.168.1.0/24"], dst_addrs=["10.5.0.1"], nat=False)]
        assert "GAP-CDE-NO-NAT" not in _gap_ids(rules, self._CDE)

    def test_no_cde_seeds_no_finding(self):
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], nat=False)]
        assert "GAP-CDE-NO-NAT" not in _gap_ids(rules, [])

    def test_deny_rule_does_not_trigger(self):
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], nat=False, action="deny")]
        assert "GAP-CDE-NO-NAT" not in _gap_ids(rules, self._CDE)

    def test_severity_is_medium(self):
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], nat=False)]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-CDE-NO-NAT")
        assert finding["severity"] == "medium"

    def test_requirement_tag(self):
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], nat=False)]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-CDE-NO-NAT")
        assert "1.4.5" in finding["requirement"]

    def test_affected_rule_listed(self):
        rules = [_rule(policy_id="99", src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"], nat=False)]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-CDE-NO-NAT")
        assert "99" in finding["affected_rules"]


# ---------------------------------------------------------------------------
# GAP-WIRELESS-CDE (Req 1.3.3)
# ---------------------------------------------------------------------------

class TestWirelessCde:
    _CDE = ["10.5.0.0/24"]

    def test_wlan_permit_to_cde_triggers(self):
        rules = [_rule(src_intf="wlan0", dst_addrs=["10.5.0.1"])]
        assert "GAP-WIRELESS-CDE" in _gap_ids(rules, self._CDE)

    def test_wifi_permit_to_cde_triggers(self):
        rules = [_rule(src_intf="wifi_guest", dst_addrs=["10.5.0.0/24"])]
        assert "GAP-WIRELESS-CDE" in _gap_ids(rules, self._CDE)

    def test_wireless_permit_to_cde_triggers(self):
        rules = [_rule(src_intf="wireless_corp", dst_addrs=["10.5.0.1"])]
        assert "GAP-WIRELESS-CDE" in _gap_ids(rules, self._CDE)

    def test_wireless_permit_to_non_cde_no_trigger(self):
        rules = [_rule(src_intf="wlan0", dst_addrs=["192.168.50.0/24"])]
        assert "GAP-WIRELESS-CDE" not in _gap_ids(rules, self._CDE)

    def test_no_wireless_intf_no_trigger(self):
        rules = [_rule(src_intf="lan", dst_addrs=["10.5.0.1"])]
        assert "GAP-WIRELESS-CDE" not in _gap_ids(rules, self._CDE)

    def test_wireless_deny_to_cde_no_trigger(self):
        rules = [_rule(src_intf="wlan0", dst_addrs=["10.5.0.1"], action="deny")]
        assert "GAP-WIRELESS-CDE" not in _gap_ids(rules, self._CDE)

    def test_no_cde_seeds_no_trigger(self):
        rules = [_rule(src_intf="wlan0", dst_addrs=["10.5.0.1"])]
        assert "GAP-WIRELESS-CDE" not in _gap_ids(rules, [])

    def test_severity_is_critical(self):
        rules = [_rule(src_intf="wlan0", dst_addrs=["10.5.0.1"])]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-WIRELESS-CDE")
        assert finding["severity"] == "critical"

    def test_requirement_tag(self):
        rules = [_rule(src_intf="wlan0", dst_addrs=["10.5.0.1"])]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-WIRELESS-CDE")
        assert "1.3.3" in finding["requirement"]

    def test_affected_rule_listed(self):
        rules = [_rule(policy_id="77", src_intf="wlan0", dst_addrs=["10.5.0.1"])]
        result = run_gap_analysis(rules, self._CDE, [])
        finding = next(f for f in result["gap_findings"] if f["id"] == "GAP-WIRELESS-CDE")
        assert "77" in finding["affected_rules"]


# ---------------------------------------------------------------------------
# Regression: all original checks still fire
# ---------------------------------------------------------------------------

class TestRegressionOriginalChecks:
    """Ensure the 5 original checks still work correctly."""

    def test_deny_all_still_fires(self):
        rules = [_rule(action="permit", src_addrs=["any"], dst_addrs=["10.0.0.1"])]
        assert "GAP-DENY-ALL" in _gap_ids(rules)

    def test_inet_to_cde_still_fires(self):
        rules = [_rule(src_addrs=["0.0.0.0/0"], dst_addrs=["10.5.0.1"])]
        assert "GAP-INET-TO-CDE" in _gap_ids(rules, ["10.5.0.0/24"])

    def test_broad_inbound_still_fires(self):
        rules = [_rule(src_addrs=["any"], dst_addrs=["any"], services=["ALL"])]
        assert "GAP-BROAD-INBOUND" in _gap_ids(rules)

    def test_cde_outbound_still_fires(self):
        rules = [_rule(src_addrs=["10.5.0.1"], dst_addrs=["0.0.0.0/0"], services=["ANY"])]
        assert "GAP-CDE-OUTBOUND" in _gap_ids(rules, ["10.5.0.0/24"])

    def test_rule_comments_still_fires(self):
        rules = [
            _rule(policy_id=str(i), action="permit", comment=None)
            for i in range(10)
        ]
        assert "GAP-RULE-COMMENTS" in _gap_ids(rules)


# ---------------------------------------------------------------------------
# Total check count integration test
# ---------------------------------------------------------------------------

class TestCheckCount:
    def test_at_least_ten_checks_can_fire(self):
        """Construct a rule set that should trigger all 10 checks."""
        cde = ["10.5.0.0/24"]
        rules = [
            # GAP-DENY-ALL: no deny-all present
            # GAP-INET-TO-CDE: internet to CDE
            {
                "policy_id": "1", "src_addrs": ["0.0.0.0/0"], "dst_addrs": ["10.5.0.1"],
                "services": ["tcp/443"], "action": "permit", "src_intf": None, "dst_intf": None,
                "nat": False, "log_traffic": True, "comment": None,
            },
            # GAP-BROAD-INBOUND: any-any-all
            {
                "policy_id": "2", "src_addrs": ["any"], "dst_addrs": ["any"],
                "services": ["ALL"], "action": "permit", "src_intf": None, "dst_intf": None,
                "nat": True, "log_traffic": True, "comment": None,
            },
            # GAP-CDE-OUTBOUND: CDE src to internet, all services
            {
                "policy_id": "3", "src_addrs": ["10.5.0.1"], "dst_addrs": ["0.0.0.0/0"],
                "services": ["ANY"], "action": "permit", "src_intf": None, "dst_intf": None,
                "nat": True, "log_traffic": True, "comment": None,
            },
            # GAP-RULE-COMMENTS: permit with no comment (already covered above + this one)
            # GAP-INSECURE-PROTO: telnet
            {
                "policy_id": "4", "src_addrs": ["192.168.1.0/24"], "dst_addrs": ["10.1.0.1"],
                "services": ["tcp/23"], "action": "permit", "src_intf": None, "dst_intf": None,
                "nat": True, "log_traffic": True, "comment": None,
            },
            # GAP-BROAD-INTERNAL-CDE: private src, CDE dst, all services
            {
                "policy_id": "5", "src_addrs": ["192.168.0.0/16"], "dst_addrs": ["10.5.0.1"],
                "services": ["ALL"], "action": "permit", "src_intf": None, "dst_intf": None,
                "nat": True, "log_traffic": True, "comment": None,
            },
            # GAP-SPOOF: private src from WAN interface
            {
                "policy_id": "6", "src_addrs": ["10.0.0.0/8"], "dst_addrs": ["10.1.0.1"],
                "services": ["tcp/443"], "action": "permit", "src_intf": "wan1", "dst_intf": None,
                "nat": True, "log_traffic": True, "comment": "spoof-test",
            },
            # GAP-CDE-NO-NAT: internet to CDE without NAT (rule 1 above already covers this)
            # GAP-WIRELESS-CDE: wlan to CDE
            {
                "policy_id": "7", "src_addrs": ["any"], "dst_addrs": ["10.5.0.1"],
                "services": ["tcp/443"], "action": "permit", "src_intf": "wlan0", "dst_intf": None,
                "nat": True, "log_traffic": True, "comment": "wireless-test",
            },
        ]
        ids = _gap_ids(rules, cde)
        expected = {
            "GAP-DENY-ALL",
            "GAP-INET-TO-CDE",
            "GAP-BROAD-INBOUND",
            "GAP-CDE-OUTBOUND",
            "GAP-RULE-COMMENTS",
            "GAP-INSECURE-PROTO",
            "GAP-BROAD-INTERNAL-CDE",
            "GAP-SPOOF",
            "GAP-CDE-NO-NAT",
            "GAP-WIRELESS-CDE",
        }
        assert expected <= ids, f"Missing checks: {expected - ids}"
