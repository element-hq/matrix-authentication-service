# METADATA
# schemas:
#   - input: schema["client_registration_input"]
package client_registration

import future.keywords.in

default allow := false

allow {
	count(violation) == 0
}

parse_uri(url) = obj {
	is_string(url)
	[matches] := regex.find_all_string_submatch_n("^(?P<scheme>[a-z][a-z0-9+.-]*):(?://(?P<host>((?:(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])\\.)*(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])|127.0.0.1|0.0.0.0|\\[::1\\])(?::(?P<port>[0-9]+))?))?(?P<path>/[A-Za-z0-9/.-]*)$", url, 1)
	obj := {"scheme": matches[1], "authority": matches[2], "host": matches[3], "port": matches[4], "path": matches[5]}
}

secure_url(x) {
	x
	data.client_registration.allow_insecure_uris
}

secure_url(x) {
	url := parse_uri(x)
	url.scheme == "https"

	# Disallow localhost variants
	url.host != "localhost"
	url.host != "127.0.0.1"
	url.host != "0.0.0.0"
	url.host != "[::1]"

	# Must be standard port for HTTPS
	url.port == ""
}

host_matches_client_uri(x) {
	x

	# Do not check we allow host mismatch
	data.client_registration.allow_host_mismatch
}

host_matches_client_uri(x) {
	x

	# Do not check if the client_uri is missing and we allow that
	data.client_registration.allow_missing_client_uri
	not data.client_metadata.client_uri
}

host_matches_client_uri(x) {
	client_uri := parse_uri(input.client_metadata.client_uri)
	uri := parse_uri(x)
	is_subdomain(client_uri.host, uri.host)
}

violation[{"msg": "missing client_uri"}] {
	not data.client_registration.allow_missing_client_uri
	not input.client_metadata.client_uri
}

violation[{"msg": "invalid client_uri"}] {
	not secure_url(input.client_metadata.client_uri)
}

violation[{"msg": "invalid tos_uri"}] {
	input.client_metadata.tos_uri
	not secure_url(input.client_metadata.tos_uri)
}

violation[{"msg": "tos_uri not on the same host as the client_uri"}] {
	input.client_metadata.tos_uri
	not host_matches_client_uri(input.client_metadata.tos_uri)
}

violation[{"msg": "invalid policy_uri"}] {
	input.client_metadata.policy_uri
	not secure_url(input.client_metadata.policy_uri)
}

violation[{"msg": "policy_uri not on the same host as the client_uri"}] {
	input.client_metadata.policy_uri
	not host_matches_client_uri(input.client_metadata.policy_uri)
}

violation[{"msg": "invalid logo_uri"}] {
	input.client_metadata.logo_uri
	not secure_url(input.client_metadata.logo_uri)
}

violation[{"msg": "logo_uri not on the same host as the client_uri"}] {
	input.client_metadata.logo_uri
	not host_matches_client_uri(input.client_metadata.logo_uri)
}

# If the grant_types is missing, we assume it is authorization_code
uses_grant_type("authorization_code") {
	not input.client_metadata.grant_types
}

# Else, we check that the grant_types contains the given grant_type
uses_grant_type(grant_type) {
	some gt in input.client_metadata.grant_types
	gt == grant_type
}

# Consider a client public if the authentication method is none
is_public_client {
	input.client_metadata.token_endpoint_auth_method == "none"
}

requires_redirect_uris {
	uses_grant_type("authorization_code")
}

requires_redirect_uris {
	uses_grant_type("implicit")
}

violation[{"msg": "client_credentials grant_type requires some form of client authentication"}] {
	uses_grant_type("client_credentials")
	is_public_client
}

violation[{"msg": "missing redirect_uris"}] {
	requires_redirect_uris
	not input.client_metadata.redirect_uris
}

violation[{"msg": "invalid redirect_uris: it must be an array"}] {
	not is_array(input.client_metadata.redirect_uris)
}

violation[{"msg": "invalid redirect_uris: it must have at least one redirect_uri"}] {
	requires_redirect_uris
	count(input.client_metadata.redirect_uris) == 0
}

# Used to verify that a reverse-dns formatted scheme is a strict subdomain of
# another host.
# This is used so a redirect_uri like 'com.example.app:/' works for
# a 'client_uri' of 'https://example.com/'
reverse_dns_match(host, reverse_dns) {
	is_string(host)
	is_string(reverse_dns)

	# Reverse the host
	host_parts := array.reverse(split(host, "."))

	# Split the already reversed DNS
	dns_parts := split(reverse_dns, ".")

	# Check that the reverse_dns strictly is a subdomain of the host
	array.slice(dns_parts, 0, count(host_parts)) == host_parts
}

# Used to verify that all the various URIs are subdomains of the client_uri
is_subdomain(host, subdomain) {
	is_string(host)
	is_string(subdomain)

	# Split the host
	host_parts := array.reverse(split(host, "."))

	# Split the subdomain
	subdomain_parts := array.reverse(split(subdomain, "."))

	# Check that the subdomain strictly is a subdomain of the host
	array.slice(subdomain_parts, 0, count(host_parts)) == host_parts
}

valid_native_redirector(x) {
	url := parse_uri(x)
	is_localhost(url.host)
	url.scheme == "http"
}

is_localhost(host) {
	host == "localhost"
}

is_localhost(host) {
	host == "127.0.0.1"
}

is_localhost(host) {
	host == "[::1]"
}

# Custom schemes should match the client_uri, reverse-dns style
# e.g. io.element.app:/ matches https://app.element.io/
valid_native_redirector(x) {
	url := parse_uri(x)
	url.scheme != "http"
	url.scheme != "https"

	# They should have no host/port
	url.authority == ""
	client_uri := parse_uri(input.client_metadata.client_uri)
	reverse_dns_match(client_uri.host, url.scheme)
}

valid_redirect_uri(uri) {
	input.client_metadata.application_type == "native"
	valid_native_redirector(uri)
}

valid_redirect_uri(uri) {
	secure_url(uri)
	host_matches_client_uri(uri)
}

violation[{"msg": "invalid redirect_uri", "redirect_uri": redirect_uri}] {
	some redirect_uri in input.client_metadata.redirect_uris
	not valid_redirect_uri(redirect_uri)
}
