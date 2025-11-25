# Copyright 2025 Element Creations Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

# METADATA
# schemas:
#   - input: schema["compat_login_input"]
package compat_login

import rego.v1

import data.common

default allow := false

allow if {
	count(violation) == 0
}

violation contains {"msg": sprintf(
	"Requester [%s] isn't allowed to do this action",
	[common.format_requester(input.requester)],
)} if {
	common.requester_banned(input.requester, data.requester)
}

violation contains {
	"code": "too-many-sessions",
	"msg": "user has too many active sessions (soft limit)",
} if {
	# Only apply if session limits are enabled in the config
	data.session_limit != null

	# This is a web-based interactive login
	input.is_interactive

	# Only apply if this login doesn't replace a session
	# (As then this login is not actually increasing the number of devices)
	not input.session_replaced

	# For web-based 'compat SSO' login, a violation occurs when the soft limit has already been
	# reached or exceeded.
	# We use the soft limit because the user will be able to interactively remove
	# sessions to return under the limit.
	data.session_limit.soft_limit <= input.session_counts.total
}

violation contains {
	"code": "too-many-sessions",
	"msg": "user has too many active sessions (hard limit)",
} if {
	# Only apply if session limits are enabled in the config
	data.session_limit != null

	# This is not a web-based interactive login
	not input.is_interactive

	# Only apply if this login doesn't replace a session
	# (As then this login is not actually increasing the number of devices)
	not input.session_replaced

	# For `m.login.password` login, a violation occurs when the hard limit has already been
	# reached or exceeded.
	# We don't use the soft limit because the user won't be able to interactively remove
	# sessions to return under the limit.
	data.session_limit.hard_limit <= input.session_counts.total
}
