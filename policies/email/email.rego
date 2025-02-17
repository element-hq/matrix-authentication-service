# METADATA
# schemas:
#   - input: schema["email_input"]
package email

import rego.v1

import data.common

default allow := false

allow if {
	count(violation) == 0
}

# Allow any domains if the data.allowed_domains array is not set
domain_allowed if {
	not data.allowed_domains
}

# Allow an email only if its domain is in the list of allowed domains
domain_allowed if {
	[_, domain] := split(input.email, "@")
	some allowed_domain in data.allowed_domains
	glob.match(allowed_domain, ["."], domain)
}

# Allow any emails if the data.emails.allowed_addresses is not set
address_allowed if {
	not data.emails.allowed_addresses
}

# Allow an email only if its address is in the list of allowed addresses
address_allowed if {
	common.matches_string_constraints(input.email, data.emails.allowed_addresses)
}

# METADATA
# entrypoint: true
violation contains {"code": "email-domain-not-allowed", "msg": "email domain is not allowed"} if {
	not domain_allowed
}

# Deny emails with their domain in the domains banlist
violation contains {"code": "email-domain-banned", "msg": "email domain is banned"} if {
	[_, domain] := split(input.email, "@")
	some banned_domain in data.banned_domains
	glob.match(banned_domain, ["."], domain)
}

# Deny emails if it's not allowed
violation contains {"code": "email-not-allowed", "msg": "email is not allowed"} if {
	not address_allowed
}

# Deny emails which match the email ban list constraint
violation contains {"code": "email-banned", "msg": "email is not allowed"} if {
	common.matches_string_constraints(input.email, data.emails.banned_addresses)
}
