"""Tests for juniper_grokoid."""

import re

import pytest

from juniper_grokoid import (
    build_extractor,
    classify_variable,
    extract_category,
    has_variables,
    parse_args,
    template_to_grok,
    variable_to_grok,
)


# ---------------------------------------------------------------------------
# template_to_grok — 6 spec test cases (exact string match)
# ---------------------------------------------------------------------------

class TestTemplateToGrok:
    """All six spec test cases with exact input/output matching."""

    def test_rt_flow_session_deny(self):
        template = (
            "session denied <variable>source-address</variable>/"
            "<variable>source-port</variable>->"
            "<variable>destination-address</variable>/"
            "<variable>destination-port</variable> "
            "0x<variable>connection-tag</variable> "
            "<variable>service-name</variable> "
            "<variable>protocol-id</variable>"
            "(<variable>icmp-type</variable>) "
            "<variable>policy-name</variable> "
            "<variable>source-zone-name</variable> "
            "<variable>destination-zone-name</variable> "
            "<variable>application</variable> "
            "<variable>nested-application</variable> "
            "<variable>username</variable>"
            "(<variable>roles</variable>) "
            "<variable>packet-incoming-interface</variable> "
            "<variable>encrypted</variable> "
            "<variable>reason</variable> "
            "<variable>session-id</variable> "
            "<variable>application-category</variable> "
            "<variable>application-sub-category</variable> "
            "<variable>application-risk</variable> "
            "<variable>application-characteristics</variable> "
            "<variable>src-vrf-grp</variable> "
            "<variable>dst-vrf-grp</variable> "
            "<variable>source-tenant</variable> "
            "<variable>destination-service</variable> "
            "<variable>user-type</variable>"
        )
        expected = (
            "session" + re.escape(" ") + "denied" + re.escape(" ")
            + "%{IP:source_address}/%{NUMBER:source_port}"
            + re.escape("->")
            + "%{IP:destination_address}/%{NUMBER:destination_port}"
            + re.escape(" ") + "0x%{DATA:connection_tag}"
            + re.escape(" ") + "%{DATA:service_name}"
            + re.escape(" ") + "%{NUMBER:protocol_id}"
            + re.escape("(") + "%{DATA:icmp_type}" + re.escape(")")
            + re.escape(" ") + "%{DATA:policy_name}"
            + re.escape(" ") + "%{DATA:source_zone_name}"
            + re.escape(" ") + "%{DATA:destination_zone_name}"
            + re.escape(" ") + "%{DATA:application}"
            + re.escape(" ") + "%{DATA:nested_application}"
            + re.escape(" ") + "%{DATA:username}"
            + re.escape("(") + "%{DATA:roles}" + re.escape(")")
            + re.escape(" ") + "%{DATA:packet_incoming_interface}"
            + re.escape(" ") + "%{DATA:encrypted}"
            + re.escape(" ") + "%{DATA:reason}"
            + re.escape(" ") + "%{NUMBER:session_id}"
            + re.escape(" ") + "%{DATA:application_category}"
            + re.escape(" ") + "%{DATA:application_sub_category}"
            + re.escape(" ") + "%{DATA:application_risk}"
            + re.escape(" ") + "%{DATA:application_characteristics}"
            + re.escape(" ") + "%{DATA:src_vrf_grp}"
            + re.escape(" ") + "%{DATA:dst_vrf_grp}"
            + re.escape(" ") + "%{DATA:source_tenant}"
            + re.escape(" ") + "%{DATA:destination_service}"
            + re.escape(" ") + "%{DATA:user_type}"
        )
        assert template_to_grok(template) == expected

    def test_pfe_fw_syslog_ip(self):
        template = (
            "FW: <variable>interface-name</variable> "
            "<variable>action</variable> "
            "<variable>protocol-name</variable> "
            "<variable>source-address</variable> "
            "<variable>destination-address</variable> "
            "<variable>source-port-or-type</variable> "
            "<variable>destination-port-or-code</variable> "
            "(<variable>count</variable> packets)"
        )
        expected = (
            "FW:" + re.escape(" ") + "%{DATA:interface_name}"
            + re.escape(" ") + "%{DATA:action}"
            + re.escape(" ") + "%{DATA:protocol_name}"
            + re.escape(" ") + "%{IP:source_address}"
            + re.escape(" ") + "%{IP:destination_address}"
            + re.escape(" ") + "%{NUMBER:source_port_or_type}"
            + re.escape(" ") + "%{NUMBER:destination_port_or_code}"
            + re.escape(" (") + "%{NUMBER:count}"
            + re.escape(" ") + "packets" + re.escape(")")
        )
        assert template_to_grok(template) == expected

    def test_webfilter_url_blocked(self):
        template = (
            'WebFilter: ACTION="URL Blocked" '
            'source-zone="<variable>source-zone</variable>" '
            'destination-zone="<variable>destination-zone</variable>"'
            "<variable>source-address</variable>"
            "(<variable>source-port</variable>)->"
            "<variable>destination-address</variable>"
            "(<variable>destination-port</variable>) "
            "SESSION_ID=<variable>session-id</variable> "
            'APPLICATION="<variable>application</variable>" '
            'NESTED-APPLICATION="<variable>nested-application</variable>"'
            'CATEGORY="<variable>category</variable>" '
            'REASON="<variable>reason</variable>" '
            'PROFILE="<variable>profile</variable>" '
            "URL=<variable>url</variable> "
            "username <variable>username</variable> "
            "roles <variable>roles</variable> "
            "application-sub-category <variable>application-sub-category</variable> "
            "urlcategory-risk <variable>urlcategory-risk</variable>"
        )
        expected = (
            re.escape('WebFilter: ACTION="URL Blocked" source-zone="')
            + "%{DATA:source_zone}"
            + re.escape('" destination-zone="')
            + "%{DATA:destination_zone}"
            + re.escape('"')
            + "%{IP:source_address}"
            + re.escape("(") + "%{NUMBER:source_port}" + re.escape(")")
            + re.escape("->")
            + "%{IP:destination_address}"
            + re.escape("(") + "%{NUMBER:destination_port}" + re.escape(")")
            + re.escape(" SESSION_ID=") + "%{NUMBER:session_id}"
            + re.escape(' APPLICATION="') + "%{DATA:application}"
            + re.escape('" NESTED-APPLICATION="') + "%{DATA:nested_application}"
            + re.escape('"CATEGORY="') + "%{DATA:category}"
            + re.escape('" REASON="') + "%{DATA:reason}"
            + re.escape('" PROFILE="') + "%{DATA:profile}"
            + re.escape('" URL=') + "%{DATA:url}"
            + re.escape(" username ") + "%{DATA:username}"
            + re.escape(" roles ") + "%{DATA:roles}"
            + re.escape(" application-sub-category ") + "%{DATA:application_sub_category}"
            + re.escape(" urlcategory-risk ") + "%{DATA:urlcategory_risk}"
        )
        assert template_to_grok(template) == expected

    def test_aamw_action_log(self):
        template = (
            "hostname=<variable>hostname</variable> "
            "file-category=<variable>file-category</variable> "
            "verdict-number=<variable>verdict-number</variable> "
            "mw-info=<variable>malware-info</variable> "
            "action=<variable>action</variable> "
            "list-hit=<variable>list-hit</variable> "
            "file-hash-lookup=<variable>file-hash-lookup</variable> "
            "source-address=<variable>source-address</variable> "
            "source-port=<variable>source-port</variable> "
            "destination-address=<variable>destination-address</variable> "
            "destination-port=<variable>destination-port</variable> "
            "protocol-id=<variable>protocol-id</variable> "
            "application=<variable>application</variable> "
            "nested-application=<variable>nested-application</variable> "
            "policy-name=<variable>policy-name</variable> "
            "username=<variable>username</variable> "
            "roles=<variable>roles</variable> "
            "session-id=<variable>session-id</variable> "
            "source-zone-name=<variable>source-zone-name</variable> "
            "destination-zone-name=<variable>destination-zone-name</variable> "
            "sample-sha256=<variable>sample-sha256</variable> "
            "file-name=<variable>file-name</variable> "
            "url=<variable>url</variable>"
        )
        expected = (
            "hostname=%{DATA:hostname}"
            + re.escape(" file-category=") + "%{DATA:file_category}"
            + re.escape(" verdict-number=") + "%{NUMBER:verdict_number}"
            + re.escape(" mw-info=") + "%{DATA:malware_info}"
            + re.escape(" action=") + "%{DATA:action}"
            + re.escape(" list-hit=") + "%{DATA:list_hit}"
            + re.escape(" file-hash-lookup=") + "%{DATA:file_hash_lookup}"
            + re.escape(" source-address=") + "%{IP:source_address}"
            + re.escape(" source-port=") + "%{NUMBER:source_port}"
            + re.escape(" destination-address=") + "%{IP:destination_address}"
            + re.escape(" destination-port=") + "%{NUMBER:destination_port}"
            + re.escape(" protocol-id=") + "%{NUMBER:protocol_id}"
            + re.escape(" application=") + "%{DATA:application}"
            + re.escape(" nested-application=") + "%{DATA:nested_application}"
            + re.escape(" policy-name=") + "%{DATA:policy_name}"
            + re.escape(" username=") + "%{DATA:username}"
            + re.escape(" roles=") + "%{DATA:roles}"
            + re.escape(" session-id=") + "%{NUMBER:session_id}"
            + re.escape(" source-zone-name=") + "%{DATA:source_zone_name}"
            + re.escape(" destination-zone-name=") + "%{DATA:destination_zone_name}"
            + re.escape(" sample-sha256=") + "%{DATA:sample_sha256}"
            + re.escape(" file-name=") + "%{DATA:file_name}"
            + re.escape(" url=") + "%{DATA:url}"
        )
        assert template_to_grok(template) == expected

    def test_rt_screen_tcp(self):
        template = (
            "<variable>attack-name</variable> "
            "source: <variable>source-address</variable>:"
            "<variable>source-port</variable>, "
            "destination: <variable>destination-address</variable>:"
            "<variable>destination-port</variable>, "
            "zone name: <variable>source-zone-name</variable>, "
            "interface name: <variable>interface-name</variable>, "
            "action: <variable>action</variable>"
        )
        expected = (
            "%{DATA:attack_name}"
            + re.escape(" source: ") + "%{IP:source_address}"
            + ":" + "%{NUMBER:source_port}"
            + re.escape(", destination: ") + "%{IP:destination_address}"
            + ":" + "%{NUMBER:destination_port}"
            + re.escape(", zone name: ") + "%{DATA:source_zone_name}"
            + re.escape(", interface name: ") + "%{DATA:interface_name}"
            + re.escape(", action: ") + "%{DATA:action}"
        )
        assert template_to_grok(template) == expected

    def test_av_virus_detected_mt(self):
        template = (
            "AntiVirus: Virus detected: "
            "SESSION_ID=<variable>session-id</variable> "
            'source-zone "<variable>source-zone</variable>" '
            'destination-zone "<variable>destination-zone</variable>" '
            "<variable>source-address</variable>:"
            "<variable>source-port</variable>->"
            "<variable>destination-address</variable>:"
            "<variable>destination-port</variable> "
            'profile-name="<variable>profile-name</variable>" '
            'file="<variable>filename</variable>" '
            'temp_file="<variable>temporary-filename</variable>" '
            'action="<variable>action</variable>" '
            'virus="<variable>name</variable>" '
            'URL="<variable>url</variable>" '
            'username="<variable>username</variable>" '
            'roles="<variable>roles</variable>"'
        )
        expected = (
            re.escape("AntiVirus: Virus detected: SESSION_ID=")
            + "%{NUMBER:session_id}"
            + re.escape(' source-zone "') + "%{DATA:source_zone}"
            + re.escape('" destination-zone "') + "%{DATA:destination_zone}"
            + re.escape('" ')
            + "%{IP:source_address}" + ":" + "%{NUMBER:source_port}"
            + re.escape("->")
            + "%{IP:destination_address}" + ":" + "%{NUMBER:destination_port}"
            + re.escape(' profile-name="') + "%{DATA:profile_name}"
            + re.escape('" file="') + "%{DATA:filename}"
            + re.escape('" temp_file="') + "%{DATA:temporary_filename}"
            + re.escape('" action="') + "%{DATA:action}"
            + re.escape('" virus="') + "%{DATA:name}"
            + re.escape('" URL="') + "%{DATA:url}"
            + re.escape('" username="') + "%{DATA:username}"
            + re.escape('" roles="') + "%{DATA:roles}"
            + re.escape('"')
        )
        assert template_to_grok(template) == expected


# ---------------------------------------------------------------------------
# classify_variable
# ---------------------------------------------------------------------------

class TestClassifyVariable:
    def test_ip_source_address(self):
        assert classify_variable("source-address") == "IP"

    def test_ip_destination_address(self):
        assert classify_variable("destination-address") == "IP"

    def test_ip_with_ip_in_name(self):
        assert classify_variable("nat-source-ip") == "IP"

    def test_not_ip_when_port_present(self):
        # "address" is present but so is "port" — should NOT be IP
        assert classify_variable("source-address-port") != "IP"

    def test_number_source_port(self):
        assert classify_variable("source-port") == "NUMBER"

    def test_number_destination_port(self):
        assert classify_variable("destination-port") == "NUMBER"

    def test_number_count(self):
        assert classify_variable("count") == "NUMBER"

    def test_number_packets(self):
        assert classify_variable("dropped-packets") == "NUMBER"

    def test_number_bytes(self):
        assert classify_variable("sent-bytes") == "NUMBER"

    def test_number_elapsed(self):
        assert classify_variable("elapsed-time") == "NUMBER"

    def test_number_verdict_number(self):
        assert classify_variable("verdict-number") == "NUMBER"

    def test_number_id_exact(self):
        assert classify_variable("id") == "NUMBER"

    def test_number_session_id(self):
        assert classify_variable("session-id") == "NUMBER"

    def test_number_protocol_id(self):
        assert classify_variable("protocol-id") == "NUMBER"

    def test_data_fallback(self):
        assert classify_variable("hostname") == "DATA"

    def test_data_action(self):
        assert classify_variable("action") == "DATA"

    def test_data_policy_name(self):
        assert classify_variable("policy-name") == "DATA"

    def test_data_username(self):
        assert classify_variable("username") == "DATA"


# ---------------------------------------------------------------------------
# extract_category
# ---------------------------------------------------------------------------

class TestExtractCategory:
    def test_security_rt_screen(self):
        assert extract_category("RT_SCREEN_TCP") == "security"

    def test_security_pfe_fw(self):
        assert extract_category("PFE_FW_SYSLOG_IP") == "security"

    def test_utm_webfilter(self):
        assert extract_category("WEBFILTER_URL_BLOCKED") == "utm"

    def test_utm_aamw(self):
        assert extract_category("AAMW_ACTION_LOG") == "utm"

    def test_utm_av(self):
        assert extract_category("AV_VIRUS_DETECTED_MT") == "utm"

    def test_flow_rt_flow(self):
        assert extract_category("RT_FLOW_SESSION_DENY") == "flow"

    def test_chassis(self):
        assert extract_category("CHASSISD_SNMP_TRAP") == "chassis"

    def test_routing_bgp(self):
        assert extract_category("BGP_NEIGHBOR_DOWN") == "routing"

    def test_routing_rpd_ospf(self):
        assert extract_category("RPD_OSPF_NBR_DOWN") == "routing"

    def test_unknown(self):
        assert extract_category("UNKNOWN_MESSAGE") is None

    def test_unknown_aaa(self):
        assert extract_category("AAA_DUP_INSTANCE") is None


# ---------------------------------------------------------------------------
# has_variables
# ---------------------------------------------------------------------------

class TestHasVariables:
    def test_with_variable(self):
        assert has_variables("source=<variable>src</variable>") is True

    def test_without_variable(self):
        assert has_variables("another instance is running") is False

    def test_empty_string(self):
        assert has_variables("") is False


# ---------------------------------------------------------------------------
# build_extractor
# ---------------------------------------------------------------------------

class TestBuildExtractor:
    def test_structure(self):
        ext = build_extractor("RT_FLOW_SESSION_DENY", "%{IP:src}", 0)
        assert ext["title"] == "RT_FLOW_SESSION_DENY"
        assert ext["extractor_type"] == "grok"
        assert ext["converters"] == []
        assert ext["order"] == 0
        assert ext["cursor_strategy"] == "copy"
        assert ext["source_field"] == "message"
        assert ext["target_field"] == ""
        assert ext["extractor_config"]["grok_pattern"] == "%{IP:src}"
        assert ext["condition_type"] == "string"
        assert ext["condition_value"] == "RT_FLOW_SESSION_DENY"

    def test_order_preserved(self):
        ext = build_extractor("TEST", "%{DATA:x}", 42)
        assert ext["order"] == 42


# ---------------------------------------------------------------------------
# CLI arg parsing
# ---------------------------------------------------------------------------

class TestParseArgs:
    def test_basic_input(self):
        args = parse_args(["-i", "test.xlsx"])
        assert args.input == "test.xlsx"
        assert args.output is None
        assert args.categories is None
        assert args.dry_run is False

    def test_comma_separated_categories(self):
        args = parse_args(["-i", "test.xlsx", "-c", "security,flow,utm"])
        assert args.categories == ["security", "flow", "utm"]

    def test_single_category(self):
        args = parse_args(["-i", "test.xlsx", "-c", "flow"])
        assert args.categories == ["flow"]

    def test_categories_with_spaces(self):
        args = parse_args(["-i", "test.xlsx", "-c", "security, flow"])
        assert args.categories == ["security", "flow"]

    def test_list_categories_no_input(self):
        args = parse_args(["--list-categories"])
        assert args.list_categories is True
        assert args.input is None

    def test_dry_run(self):
        args = parse_args(["-i", "test.xlsx", "--dry-run"])
        assert args.dry_run is True

    def test_graylog_version_default(self):
        args = parse_args(["-i", "test.xlsx"])
        assert args.graylog_version == "5.0.13"

    def test_graylog_version_custom(self):
        args = parse_args(["-i", "test.xlsx", "--graylog-version", "6.0.0"])
        assert args.graylog_version == "6.0.0"

    def test_missing_input_without_list_categories(self):
        with pytest.raises(SystemExit):
            parse_args([])
