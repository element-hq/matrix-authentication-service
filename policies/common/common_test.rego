package common_test

import data.common
import rego.v1

test_match_literals if {
	common.matches_string_constraints("literal", {"literals": ["literal"]})
	not common.matches_string_constraints("literal", {"literals": ["lit"]})
}

test_match_substring if {
	common.matches_string_constraints("some string", {"substrings": ["str"]})
	not common.matches_string_constraints("some string", {"substrings": ["something"]})
}

test_match_regex if {
	common.matches_string_constraints("some string", {"regexes": ["^some"]})
	not common.matches_string_constraints("some string", {"regexes": ["^string"]})
}

test_match_prefix if {
	common.matches_string_constraints("some string", {"prefixes": ["some"]})
	not common.matches_string_constraints("some string", {"prefixes": ["string"]})
}

test_match_suffix if {
	common.matches_string_constraints("some string", {"suffixes": ["string"]})
	not common.matches_string_constraints("some string", {"suffixes": ["some"]})
}

test_ip_in_list if {
	common.ip_in_list("192.168.1.1", ["192.168.1.1"])
	common.ip_in_list("192.168.1.1", ["192.168.1.0/24"])
	common.ip_in_list("::1", ["::1"])
	common.ip_in_list("::1", ["::/64"])
	not common.ip_in_list("192.168.1.1", ["192.168.1.2/32"])
}

test_requester_banned if {
	common.requester_banned(
		{"ip_address": "192.168.1.1", "user_agent": "Mozilla/5.0"},
		{"banned_ips": ["192.168.1.1"]},
	)
}
