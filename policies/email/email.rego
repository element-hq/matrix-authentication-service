# METADATA
# schemas:
#   - input: schema["email_input"]
package email

import rego.v1

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
