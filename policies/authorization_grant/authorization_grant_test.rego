# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

package authorization_grant_test

import data.authorization_grant
import rego.v1

user := {"username": "john"}

client := {"client_id": "client"}

test_standard_scopes if {
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.scope as ""

	authorization_grant.allow with input.user as user
		with input.client as client
		with input.scope as "openid"

	authorization_grant.allow with input.user as user
		with input.client as client
		with input.scope as "email"

	authorization_grant.allow with input.user as user
		with input.client as client
		with input.scope as "openid email"

	# Not supported yet
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.scope as "phone"

	# Not supported yet
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.scope as "profile"
}

test_matrix_unstable_scopes if {
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:*"

	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:*"

	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "client_credentials"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:*"
}

test_matrix_stable_scopes if {
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:client:api:*"

	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:matrix:client:api:*"

	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "client_credentials"
		with input.scope as "urn:matrix:client:api:*"
}

test_unstable_device_scopes if {
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"

	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01-asdasdsa1-2313"

	# Too short
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abcd"

	# Multiple device scope
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01 urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd02"

	# Allowed with the device code grant
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"

	# Not authorization_grant.allowed for the client credentials grant
	not authorization_grant.allow with input.client as client
		with input.grant_type as "client_credentials"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"
}

test_stable_device_scopes if {
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:client:api:* urn:matrix:client:device:AAbbCCdd01"

	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:client:api:* urn:matrix:client:device:AAbbCCdd01-asdasdsa1-2313"

	# Too short
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:client:api:* urn:matrix:client:device:abcd"

	# Multiple device scope
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:client:api:* urn:matrix:client:device:AAbbCCdd01 urn:matrix:client:device:AAbbCCdd02"

	# Allowed with the device code grant
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:matrix:client:api:* urn:matrix:client:device:AAbbCCdd01"

	# Not authorization_grant.allowed for the client credentials grant
	not authorization_grant.allow with input.client as client
		with input.grant_type as "client_credentials"
		with input.scope as "urn:matrix:client:api:* urn:matrix:client:device:AAbbCCdd01"
}

test_device_scope_only_with_cs_api_scope if {
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		# Requested a device scope but no C-S API scope:
with 		input.scope as "urn:matrix:client:device:AAbbCCdd01"

	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		# Requested a device scope but no C-S API scope:
with 		input.scope as "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"
}

test_mix_stable_and_unstable_scopes if {
	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:client:device:AAbbCCdd01"

	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:client:api:* urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"

	not authorization_grant.allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:client:api:* urn:matrix:org.matrix.msc2967.client:api:*"
}

test_synapse_admin_scopes if {
	some grant_type in ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"]

	authorization_grant.allow with input.user as user
		with input.client as client
		with data.admin_users as ["john"]
		with input.grant_type as grant_type
		with input.scope as "urn:synapse:admin:*"

	not authorization_grant.allow with input.user as user
		with input.client as client
		with data.admin_users as []
		with input.grant_type as grant_type
		with input.scope as "urn:synapse:admin:*"

	authorization_grant.allow with input.user as user
		with input.user.can_request_admin as true
		with input.client as client
		with data.admin_users as []
		with input.grant_type as grant_type
		with input.scope as "urn:synapse:admin:*"

	not authorization_grant.allow with input.user as user
		with input.user.can_request_admin as false
		with input.client as client
		with data.admin_users as []
		with input.grant_type as grant_type
		with input.scope as "urn:synapse:admin:*"
}

test_mas_scopes if {
	authorization_grant.allow with input.user as user
		with input.client as client
		with input.scope as "urn:mas:graphql:*"

	authorization_grant.allow with input.user as user
		with input.client as client
		with data.admin_users as ["john"]
		with input.grant_type as "authorization_code"
		with input.scope as "urn:mas:admin"

	not authorization_grant.allow with input.user as user
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "authorization_code"
		with input.scope as "urn:mas:admin"
}
