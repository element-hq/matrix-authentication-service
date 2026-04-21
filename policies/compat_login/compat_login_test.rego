# Copyright 2025 Element Creations Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

package compat_login_test

import data.compat_login
import rego.v1

user := {"username": "john"}

# Helper utility to extract the number of sessions that they `need_to_remove`, returns 0
# if the `too-many-sessions` violation is not found
get_need_to_remove(violations) := need if {
	some v in violations
	v.code == "too-many-sessions"
	need := v.need_to_remove
} else := 0

# Tests session limiting when using (the interactive part of) `m.login.sso`
# (interactive, therefore `soft_limit` applies)
# =========================================================================
test_session_limiting_sso_under_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 1}
		with input.login as {"type": "m.login.sso"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	result.allow
	result.need_to_remove == 0
}

test_session_limiting_sso_barely_under_soft_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 31}
		with input.login as {"type": "m.login.sso"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	result.allow
	result.need_to_remove == 0
}

test_session_limiting_sso_hit_soft_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 32}
		with input.login as {"type": "m.login.sso"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	not result.allow
	result.need_to_remove == 1
}

test_session_limiting_sso_over_soft_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 42}
		with input.login as {"type": "m.login.sso"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	not result.allow
	result.need_to_remove == 11
}

test_session_limiting_sso_over_hard_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 65}
		with input.login as {"type": "m.login.sso"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	not result.allow
	# Only the `soft_limit` applies to the interactive `m.login.sso` login
	result.need_to_remove == 34
}

test_session_limiting_sso_no_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 1}
		with input.login as {"type": "m.login.sso"}
		with input.session_replaced as false
		# No limit configured
		with data.session_limit as null
	result.allow
	result.need_to_remove == 0
}

# Test session limiting when using `m.login.password` (not interactive, therefore
# `hard_limit` applies)
# =========================================================================
test_session_limiting_password_under_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 1}
		with input.login as {"type": "m.login.password"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	result.allow
	result.need_to_remove == 0
}

test_session_limiting_password_under_hard_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 63}
		with input.login as {"type": "m.login.password"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	result.allow
	result.need_to_remove == 0
}

test_session_limiting_password_hit_hard_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 64}
		with input.login as {"type": "m.login.password"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	not result.allow
	result.need_to_remove == 1
}

test_session_limiting_password_over_hard_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 65}
		with input.login as {"type": "m.login.password"}
		with input.session_replaced as false
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	not result.allow
	result.need_to_remove == 2
}

test_session_limiting_password_no_limit if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 1}
		with input.login as {"type": "m.login.password"}
		with input.session_replaced as false
		# No limit configured
		with data.session_limit as null
	result.allow
	result.need_to_remove == 0
}

# If the session is replacing an existing session, no need to throw any violations about
# too many sessions
test_no_session_limiting_sso_upon_replacement if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 65}
		with input.login as {"type": "m.login.sso"}
		with input.session_replaced as true
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	result.allow
	result.need_to_remove == 0
}

test_no_session_limiting_password_upon_replacement if {
	result := {
		"allow": compat_login.allow,
		"need_to_remove": get_need_to_remove(compat_login.violation),
	} with input.user as user
		with input.session_counts as {"total": 65}
		with input.login as {"type": "m.login.password"}
		with input.session_replaced as true
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}
	result.allow
	result.need_to_remove == 0
}
