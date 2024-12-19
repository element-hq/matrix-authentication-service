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
