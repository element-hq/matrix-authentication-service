# METADATA
# schemas:
#   - input: schema["authorization_grant_input"]
package authorization_grant

import rego.v1

import data.common

default allow := false

allow if {
	count(violation) == 0
}

# Users can request admin scopes if either:
# 1. They are in the admin_users list
can_request_admin(user) if {
	some admin_user in data.admin_users
	user.username == admin_user
}

# 2. They have the can_request_admin flag set to true
can_request_admin(user) if {
	user.can_request_admin
}

interactive_grant_type("authorization_code") := true

interactive_grant_type("urn:ietf:params:oauth:grant-type:device_code") := true

# Special case to make empty scope work
allowed_scope("") := true

allowed_scope("openid") := true

allowed_scope("email") := true

# This grants access to Synapse's admin API endpoints
allowed_scope("urn:synapse:admin:*") if {
	# Synapse doesn't support user-less tokens yet, so access to the admin API
	# can only be used with an authorization_code grant or a device code grant
	# as the user is present
	interactive_grant_type(input.grant_type)
	can_request_admin(input.user)
}

# This grants access to the /graphql API endpoint
allowed_scope("urn:mas:graphql:*") := true

# This makes it possible to query and do anything in the GraphQL API as an admin
allowed_scope("urn:mas:admin") if {
	interactive_grant_type(input.grant_type)
	can_request_admin(input.user)
}

# This makes it possible to get the admin scope for clients that are allowed
allowed_scope("urn:mas:admin") if {
	input.grant_type == "client_credentials"
	some client in data.admin_clients
	input.client.id == client
}

allowed_scope(scope) if {
	# Grant access to the C-S API only if there is a user
	interactive_grant_type(input.grant_type)
	regex.match(`^urn:matrix:org.matrix.msc2967.client:device:[A-Za-z0-9._~!$&'()*+,;=:@/-]{10,}$`, scope)
}

allowed_scope("urn:matrix:org.matrix.msc2967.client:api:*") if {
	# Grant access to the C-S API only if there is a user
	interactive_grant_type(input.grant_type)
}

# METADATA
# entrypoint: true
violation contains {"msg": msg} if {
	some scope in split(input.scope, " ")
	not allowed_scope(scope)
	msg := sprintf("scope '%s' not allowed", [scope])
}

violation contains {"msg": "only one device scope is allowed at a time"} if {
	scope_list := split(input.scope, " ")
	count({scope | some scope in scope_list; startswith(scope, "urn:matrix:org.matrix.msc2967.client:device:")}) > 1
}

violation contains {"msg": sprintf(
	"Requester [%s] isn't allowed to do this action",
	[common.format_requester(input.requester)],
)} if {
	common.requester_banned(input.requester, data.requester)
}
