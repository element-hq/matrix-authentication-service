# METADATA
# schemas:
#   - input: schema["client_registration_input"]
package client_registration

import rego.v1

default allow := false

allow if {
	count(violation) == 0
}

parse_uri(url) := obj if {
	is_string(url)
	url_regex := `^(?P<scheme>[a-z][a-z0-9+.-]*):(?://(?P<host>((?:(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])\.)*(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])|127.0.0.1|0.0.0.0|\[::1\])(?::(?P<port>[0-9]+))?))?(?P<path>/[A-Za-z0-9/.-]*)?(?P<query>\?[-a-zA-Z0-9()@:%_+.~#?&/=]*)?$`
	[matches] := regex.find_all_string_submatch_n(url_regex, url, 1)
	obj := {"scheme": matches[1], "authority": matches[2], "host": matches[3], "port": matches[4], "path": matches[5], "query": matches[6]}
}

secure_url(_) if {
	data.client_registration.allow_insecure_uris
}

secure_url(x) if {
	url := parse_uri(x)
	url.scheme == "https"

	# Disallow localhost variants
	url.host != "localhost"
	url.host != "127.0.0.1"
	url.host != "0.0.0.0"
	url.host != "[::1]"
}

host_matches_client_uri(_) if {
	# Do not check we allow host mismatch
	data.client_registration.allow_host_mismatch
}

host_matches_client_uri(_) if {
	# Do not check if the client_uri is missing and we allow that
	data.client_registration.allow_missing_client_uri
	not data.client_metadata.client_uri
}

host_matches_client_uri(x) if {
	client_uri := parse_uri(input.client_metadata.client_uri)
	uri := parse_uri(x)
	is_subdomain(client_uri.host, uri.host)
}

# If the grant_types is missing, we assume it is authorization_code
uses_grant_type("authorization_code", client_metadata) if {
	not client_metadata.grant_types
}

# Else, we check that the grant_types contains the given grant_type
uses_grant_type(grant_type, client_metadata) if {
	some grant in client_metadata.grant_types
	grant == grant_type
}

# Consider a client public if the authentication method is none
is_public_client if {
	input.client_metadata.token_endpoint_auth_method == "none"
}

requires_redirect_uris if {
	uses_grant_type("authorization_code", input.client_metadata)
}

requires_redirect_uris if {
	uses_grant_type("implicit", input.client_metadata)
}

# Used to verify that a reverse-dns formatted scheme is a strict subdomain of
# another host.
# This is used so a redirect_uri like 'com.example.app:/' works for
# a 'client_uri' of 'https://example.com/'
reverse_dns_match(host, reverse_dns) if {
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
is_subdomain(host, subdomain) if {
	is_string(host)
	is_string(subdomain)

	# Split the host
	host_parts := array.reverse(split(host, "."))

	# Split the subdomain
	subdomain_parts := array.reverse(split(subdomain, "."))

	# Check that the subdomain strictly is a subdomain of the host
	array.slice(subdomain_parts, 0, count(host_parts)) == host_parts
}

is_localhost("localhost")

is_localhost("127.0.0.1")

is_localhost("[::1]")

valid_native_redirector(x) if {
	url := parse_uri(x)
	is_localhost(url.host)
	url.scheme == "http"
}

# Custom schemes should match the client_uri, reverse-dns style
# e.g. io.element.app:/ matches https://app.element.io/
valid_native_redirector(x) if {
	url := parse_uri(x)
	url.scheme != "http"
	url.scheme != "https"

	# They should have no host/port
	url.authority == ""
	client_uri := parse_uri(input.client_metadata.client_uri)
	reverse_dns_match(client_uri.host, url.scheme)
}

valid_redirect_uri(uri) if {
	input.client_metadata.application_type == "native"
	valid_native_redirector(uri)
}

valid_redirect_uri(uri) if {
	secure_url(uri)
	host_matches_client_uri(uri)
}

# METADATA
# entrypoint: true
violation contains {"msg": "missing client_uri"} if {
	not data.client_registration.allow_missing_client_uri
	not input.client_metadata.client_uri
}

violation contains {"msg": "invalid client_uri"} if {
	not secure_url(input.client_metadata.client_uri)
}

violation contains {"msg": "invalid tos_uri"} if {
	not secure_url(input.client_metadata.tos_uri)
}

violation contains {"msg": "tos_uri not on the same host as the client_uri"} if {
	not host_matches_client_uri(input.client_metadata.tos_uri)
}

violation contains {"msg": "invalid policy_uri"} if {
	not secure_url(input.client_metadata.policy_uri)
}

violation contains {"msg": "policy_uri not on the same host as the client_uri"} if {
	not host_matches_client_uri(input.client_metadata.policy_uri)
}

violation contains {"msg": "invalid logo_uri"} if {
	not secure_url(input.client_metadata.logo_uri)
}

violation contains {"msg": "logo_uri not on the same host as the client_uri"} if {
	not host_matches_client_uri(input.client_metadata.logo_uri)
}

violation contains {"msg": "client_credentials grant_type requires some form of client authentication"} if {
	uses_grant_type("client_credentials", input.client_metadata)
	is_public_client
}

violation contains {"msg": "missing redirect_uris"} if {
	requires_redirect_uris
	not input.client_metadata.redirect_uris
}

violation contains {"msg": "invalid redirect_uris: it must be an array"} if {
	not is_array(input.client_metadata.redirect_uris)
}

violation contains {"msg": "invalid redirect_uris: it must have at least one redirect_uri"} if {
	requires_redirect_uris
	count(input.client_metadata.redirect_uris) == 0
}

violation contains {"msg": "invalid redirect_uri", "redirect_uri": redirect_uri} if {
	some redirect_uri in input.client_metadata.redirect_uris
	not valid_redirect_uri(redirect_uri)
}
