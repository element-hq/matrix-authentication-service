# METADATA
# schemas:
#   - input: schema["register_input"]
package register

import rego.v1

import data.email as email_policy

default allow := false

allow if {
	count(violation) == 0
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

is_ip_banned(ip) if {
	some cidr in data.registration.banned_ips
	net.cidr_contains(normalize_cidr(cidr), ip)
}

mxid(username, server_name) := sprintf("@%s:%s", [username, server_name])

# METADATA
# entrypoint: true
violation contains {"field": "username", "code": "username-too-short", "msg": "username too short"} if {
	count(input.username) == 0
}

violation contains {"field": "username", "code": "username-too-long", "msg": "username too long"} if {
	user_id := mxid(input.username, data.server_name)
	count(user_id) > 255
}

violation contains {
	"field": "username", "code": "username-all-numeric",
	"msg": "username must contain at least one non-numeric character",
} if {
	regex.match(`^[0-9]+$`, input.username)
}

violation contains {
	"field": "username", "code": "username-invalid-chars",
	"msg": "username contains invalid characters",
} if {
	not regex.match(`^[a-z0-9.=_/-]+$`, input.username)
}

violation contains {"msg": "unspecified registration method"} if {
	not input.registration_method
}

violation contains {"msg": "unknown registration method"} if {
	not input.registration_method in ["password", "upstream-oauth2"]
}

violation contains {"msg": "IP address is banned"} if {
	is_ip_banned(input.requester.ip_address)
}

# Check that we supplied an email for password registration
violation contains {"field": "email", "msg": "email required for password-based registration"} if {
	input.registration_method == "password"

	not input.email
}

# Check if the email is valid using the email policy
# and add the email field to the violation object
violation contains object.union({"field": "email"}, v) if {
	# Check if we have an email set in the input
	input.email

	# Get the violation object from the email policy
	some v in email_policy.violation
}
