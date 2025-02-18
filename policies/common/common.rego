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

format_requester(requester) := "unknown" if {
	not requester.ip_address
	not requester.user_agent
}

format_requester(requester) := sprintf("%s / %s", [requester.ip_address, requester.user_agent]) if {
	requester.ip_address
	requester.user_agent
}

format_requester(requester) := sprintf("%s", [requester.ip_address]) if {
	requester.ip_address
	not requester.user_agent
}

format_requester(requester) := sprintf("%s", [requester.user_agent]) if {
	not requester.ip_address
	requester.user_agent
}
