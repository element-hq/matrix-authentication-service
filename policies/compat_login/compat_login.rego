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
	# `+ 1` because when you're at 2 sessions, and the limit is 2, you have to make room
	# for the new session
	"need_to_remove": (against_limit - effective_session_limit.soft_limit) + 1,
} if {
	# Only apply if session limits are enabled
	effective_session_limit != null

	# This is a web-based interactive login (like `m.login.sso`)
	is_interactive

	# Only apply if this login doesn't replace a session
	# (As then this login is not actually increasing the number of devices)
	not input.session_replaced

	# Only apply limits to accounts under the threshold (if configured)
	passes_session_threshold

	# For web-based 'compat SSO' login, a violation occurs when the soft limit has already been
	# reached or exceeded.
	# We use the soft limit because the user will be able to interactively remove
	# sessions to return under the limit.
	effective_session_limit.soft_limit <= against_limit
}

violation contains {
	"code": "too-many-sessions",
	"msg": "user has too many active sessions (hard limit)",
	# `+ 1` because when you're at 2 sessions, and the limit is 2, you have to make room
	# for the new session
	"need_to_remove": (against_limit - effective_session_limit.hard_limit) + 1,
} if {
	# Only apply if session limits are enabled
	effective_session_limit != null

	# This is *not* a web-based interactive login (like `m.login.password`)
	not is_interactive

	# Only apply if this login doesn't replace a session
	# (As then this login is not actually increasing the number of devices)
	not input.session_replaced

	# Only apply limits to accounts under the threshold (if configured)
	passes_session_threshold

	# For `m.login.password` login, a violation occurs when the hard limit has already been
	# reached or exceeded.
	# We don't use the soft limit because the user won't be able to interactively remove
	# sessions to return under the limit.
	effective_session_limit.hard_limit <= against_limit
}

is_interactive if {
	# Only `m.login.sso` (the interactive web form) is interactive;
	# `m.login.password` and `m.login.token` (including the finalisation of an SSO login) are not
	input.login.type == "m.login.sso"
}

# Prefer limits from the evaluation input (per-user / per-client); fall back to
# static policy data for custom policies that only set `data.session_limit`.
# `else` is required so this is defined when `data.session_limit` is undefined
# (`object.get` is undefined if its default argument is undefined).
effective_session_limit := input.session_limit if {
	input.session_limit
} else := data.session_limit

against_limit := object.get(input.session_counts, "against_limit", input.session_counts.total)

# The session limits only apply to accounts within the `max_session_threshold`.
#
# True if the `session_limit` isn't configured or <= `max_session_threshold`.
passes_session_threshold if {
	# If no `session_limit` configured, automatically passes (undefined)
	not effective_session_limit
} else if {
	# If no `session_limit` configured, automatically passes (null)
	effective_session_limit == null
} else if {
	# If no `max_session_threshold` configured, automatically passes (undefined)
	not effective_session_limit.max_session_threshold
} else if {
	# If no `max_session_threshold` configured, automatically passes (null)
	effective_session_limit.max_session_threshold == null
} else if {
	# Otherwise, check whether the counted sessions are under the threshold
	against_limit <= effective_session_limit.max_session_threshold
}
