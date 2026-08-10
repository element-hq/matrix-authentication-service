# Copyright 2025, 2026 Element Creations Ltd.
# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

package common

import rego.v1

matches_string_constraints(str, constraints) if matches_regexes(str, constraints.regexes)

matches_string_constraints(str, constraints) if matches_substrings(str, constraints.substrings)

matches_string_constraints(str, constraints) if matches_literals(str, constraints.literals)

matches_string_constraints(str, constraints) if matches_suffixes(str, constraints.suffixes)

matches_string_constraints(str, constraints) if matches_prefixes(str, constraints.prefixes)

matches_regexes(str, regexes) if {
	some pattern in regexes
	regex.match(pattern, str)
}

matches_substrings(str, substrings) if {
	some pattern in substrings
	contains(str, pattern)
}

matches_literals(str, literals) if {
	some literal in literals
	str == literal
}

matches_suffixes(str, suffixes) if {
	some suffix in suffixes
	endswith(str, suffix)
}

matches_prefixes(str, prefixes) if {
	some prefix in prefixes
	startswith(str, prefix)
}

# Normalize an IP address or CIDR to a CIDR
normalize_cidr(ip) := ip if contains(ip, "/")

# If it's an IPv4, append /32
normalize_cidr(ip) := sprintf("%s/32", [ip]) if {
	not contains(ip, "/")
	not contains(ip, ":")
}

# If it's an IPv6, append /128
normalize_cidr(ip) := sprintf("%s/128", [ip]) if {
	not contains(ip, "/")
	contains(ip, ":")
}

ip_in_list(ip, list) if {
	some cidr in list
	net.cidr_contains(normalize_cidr(cidr), ip)
}

mxid(username, server_name) := sprintf("@%s:%s", [username, server_name])

requester_banned(requester, policy) if ip_in_list(requester.ip_address, policy.banned_ips)

requester_banned(requester, policy) if matches_string_constraints(requester.user_agent, policy.banned_user_agents)

# The fields are `null` (not absent) when unknown: a bare `requester.user_agent`
# check lets `null` through to `sprintf`, which aborts the WASM evaluation. The
# helper rule is undefined for both null and absent values, which `not` handles.
requester_has(requester, key) if is_string(requester[key])

format_requester(requester) := "unknown" if {
	not requester_has(requester, "ip_address")
	not requester_has(requester, "user_agent")
}

format_requester(requester) := sprintf("%s / %s", [requester.ip_address, requester.user_agent]) if {
	requester_has(requester, "ip_address")
	requester_has(requester, "user_agent")
}

format_requester(requester) := requester.ip_address if {
	requester_has(requester, "ip_address")
	not requester_has(requester, "user_agent")
}

format_requester(requester) := requester.user_agent if {
	not requester_has(requester, "ip_address")
	requester_has(requester, "user_agent")
}
