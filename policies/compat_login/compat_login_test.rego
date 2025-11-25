# Copyright 2025 Element Creations Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

package compat_login_test

import data.compat_login
import rego.v1

user := {"username": "john"}

test_session_limiting_sso if {
	compat_login.allow with input.user as user
		with input.session_counts as {"total": 1}
		with input.login_type as "m.login.sso"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	compat_login.allow with input.user as user
		with input.session_counts as {"total": 31}
		with input.login_type as "m.login.sso"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	not compat_login.allow with input.user as user
		with input.session_counts as {"total": 32}
		with input.login_type as "m.login.sso"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	not compat_login.allow with input.user as user
		with input.session_counts as {"total": 42}
		with input.login_type as "m.login.sso"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	not compat_login.allow with input.user as user
		with input.session_counts as {"total": 65}
		with input.login_type as "m.login.sso"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	# No limit configured
	compat_login.allow with input.user as user
		with input.session_counts as {"total": 1}
		with input.login_type as "m.login.sso"
		with data.session_limit as null
}

test_session_limiting_password if {
	compat_login.allow with input.user as user
		with input.session_counts as {"total": 1}
		with input.login_type as "m.login.password"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	compat_login.allow with input.user as user
		with input.session_counts as {"total": 63}
		with input.login_type as "m.login.password"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	not compat_login.allow with input.user as user
		with input.session_counts as {"total": 64}
		with input.login_type as "m.login.password"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	not compat_login.allow with input.user as user
		with input.session_counts as {"total": 65}
		with input.login_type as "m.login.password"
		with data.session_limit as {"soft_limit": 32, "hard_limit": 64}

	# No limit configured
	compat_login.allow with input.user as user
		with input.session_counts as {"total": 1}
		with input.login_type as "m.login.password"
		with data.session_limit as null
}
