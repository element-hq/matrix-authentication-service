# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

# METADATA
# schemas:
#   - input: schema["register_input"]
package register

import rego.v1

import data.common
import data.email as email_policy

default allow := false

allow if {
	count(violation) == 0
}

username_allowed if {
	not data.registration.allowed_usernames
}

username_allowed if {
	common.matches_string_constraints(input.username, data.registration.allowed_usernames)
}

# METADATA
# entrypoint: true
violation contains {"field": "username", "code": "username-too-short", "msg": "username too short"} if {
	count(input.username) == 0
}

violation contains {"field": "username", "code": "username-too-long", "msg": "username too long"} if {
	user_id := common.mxid(input.username, data.server_name)
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
	not regex.match(`^[a-z0-9.=_/+-]+$`, input.username)
}

violation contains {
	"field": "username", "code": "username-banned",
	"msg": "username is banned",
} if {
	common.matches_string_constraints(input.username, data.registration.banned_usernames)
}

violation contains {
	"field": "username", "code": "username-not-allowed",
	"msg": "username is not allowed",
} if {
	not username_allowed
}

violation contains {"msg": "unspecified registration method"} if {
	not input.registration_method
}

violation contains {"msg": "unknown registration method"} if {
	not input.registration_method in ["password", "upstream-oauth2"]
}

violation contains {"msg": sprintf(
	"Requester [%s] isn't allowed to do this action",
	[common.format_requester(input.requester)],
)} if {
	common.requester_banned(input.requester, data.requester)
}

# Check if the email is valid using the email policy
# and add the email field to the violation object
violation contains object.union({"field": "email"}, v) if {
	# Check if we have an email set in the input
	input.email

	# Get the violation object from the email policy
	some v in email_policy.violation
}
