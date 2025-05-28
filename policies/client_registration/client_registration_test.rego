package client_registration_test

import rego.v1

import data.client_registration

test_valid if {
	client_registration.allow with input.client_metadata as {
		"grant_types": ["authorization_code"],
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback"],
	}
}

test_missing_client_uri if {
	not client_registration.allow with input.client_metadata as {"grant_types": []}

	client_registration.allow with input.client_metadata as {"grant_types": []}
		with client_registration.allow_missing_client_uri as true
}

test_insecure_client_uri if {
	not client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "http://example.com/",
	}
}

test_tos_uri if {
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.com/tos",
	}
}

test_tos_uri_insecure if {
	# Insecure
	not client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "http://example.com/tos",
	}

	# Insecure, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "http://example.com/tos",
	}
		with client_registration.allow_insecure_uris as true
}

test_tos_uri_host_mismatch if {
	# Host mistmatch
	not client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.org/tos",
	}

	# TOS on a subdomain of the client_uri host is allowed
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://tos.example.com/",
	}

	# Host mistmatch, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.org/tos",
	}
		with client_registration.allow_host_mismatch as true
}

test_logo_uri if {
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.com/logo.png",
	}
}

test_logo_uri_insecure if {
	# Insecure
	not client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "http://example.com/logo.png",
	}

	# Insecure, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "http://example.com/logo.png",
	}
		with client_registration.allow_insecure_uris as true
}

test_logo_uri_host_mismatch if {
	# Host mistmatch
	not client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.org/logo.png",
	}

	# Logo on a subdomain of the client_uri host is allowed
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://static.example.com/logo.png",
	}

	# Host mistmatch, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.org/logo.png",
	}
		with client_registration.allow_host_mismatch as true
}

test_policy_uri if {
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.com/policy",
	}
}

test_policy_uri_insecure if {
	# Insecure
	not client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "http://example.com/policy",
	}

	# Insecure, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "http://example.com/policy",
	}
		with client_registration.allow_insecure_uris as true
}

test_policy_uri_host_mismatch if {
	# Host mistmatch
	not client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.org/policy",
	}

	# Policy on a subdomain of the client_uri host is allowed
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://policy.example.com/",
	}

	# Host mistmatch, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.org/policy",
	}
		with client_registration.allow_host_mismatch as true
}

test_redirect_uris if {
	# Missing redirect_uris
	not client_registration.allow with input.client_metadata as {"client_uri": "https://example.com/"}

	# redirect_uris is not an array
	not client_registration.allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": "https://example.com/callback",
	}

	# Empty redirect_uris
	not client_registration.allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": [],
	}

	# Not required for the client_credentials grant
	client_registration.allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		"client_uri": "https://example.com/",
	}

	# Required for the authorization_code grant
	not client_registration.allow with input.client_metadata as {
		"grant_types": ["client_credentials", "refresh_token", "authorization_code"],
		"client_uri": "https://example.com/",
	}

	# Required for the implicit grant
	not client_registration.allow with input.client_metadata as {
		"grant_types": ["client_credentials", "implicit"],
		"client_uri": "https://example.com/",
	}
}

test_web_redirect_uri if {
	client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/second/callback", "https://example.com/callback", "https://example.com/callback?query=value"],
	}

	client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "http://localhost:8080",
		"redirect_uris": ["http://localhost:8080/?no_universal_links=true"],
	}
		with client_registration.allow_insecure_uris as true

	# HTTPS redirect_uri with non-standard port
	client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com:8443/callback"],
	}
}

test_web_redirect_uri_insecure if {
	# Insecure URL
	not client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://example.com/callback", "https://example.com/callback"],
	}

	# Insecure URL, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://example.com/callback", "https://example.com/callback"],
	}
		with client_registration.allow_insecure_uris as true
}

test_web_redirect_uri_host_mismatch if {
	# Host mismatch
	not client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/second/callback", "https://example.org/callback"],
	}

	# Host mismatch, but allowed by the config
	client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/second/callback", "https://example.org/callback"],
	}
		with client_registration.allow_host_mismatch as true

	# Redirect URI on a subdomain of the client_uri host is allowed
	client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://app.example.com/callback"],
	}
}

test_web_redirect_uri_no_custom_scheme if {
	# No custom scheme allowed
	not client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["com.example.app:/callback"],
	}
}

test_web_redirect_uri_localhost_not_allowed if {
	# localhost not allowed
	not client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://locahost:1234/callback"],
	}

	# localhost not allowed
	not client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://127.0.0.1:1234/callback"],
	}

	# localhost not allowed
	not client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://[::1]:1234/callback"],
	}
}

test_web_redirect_uri_with_query if {
	client_registration.allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback?query=value", "https://example.com?query=value"],
	}
}

test_native_redirect_uri_allowed if {
	# This has all the redirect URIs types we're supporting for native apps
	client_registration.allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": [
			"com.example.app:/callback",
			"http://localhost/callback",
			"http://localhost:1234/callback",
			"http://127.0.0.1/callback",
			"http://127.0.0.1:1234/callback",
			"http://[::1]/callback",
			"http://[::1]:1234/callback",
			"https://example.com/callback",
		],
	}
}

test_native_redirect_uri_denied_domain if {
	# But not insecure
	not client_registration.allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://example.com/"],
	}

	# And not a mismatch
	not client_registration.allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://bad.com/"],
	}
}

test_native_redirect_uri_denied_on_localhost if {
	# We don't allow HTTPS on localhost
	not client_registration.allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://localhost:1234/"],
	}

	# Ensure we're not allowing localhost as a prefix
	not client_registration.allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://localhost.com/"],
	}
}

test_native_redirect_uri_custom_scheme if {
	# For custom schemes, it should match the client_uri hostname
	not client_registration.allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["org.example.app:/callback"],
	}
}

test_reverse_dns_match_parse if {
	client_uri := client_registration.parse_uri("https://element.io/")
	redirect_uri := client_registration.parse_uri("io.element.app:/callback")
	client_registration.reverse_dns_match(client_uri.host, redirect_uri.scheme)
}

test_client_credentials_grant if {
	# Allowed for confidential clients
	client_registration.allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		"token_endpoint_auth_method": "client_secret_basic",
		"client_uri": "https://example.com/",
	}
	client_registration.allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		# If omitted, defaults to "client_secret_basic"
		"client_uri": "https://example.com/",
	}

	# Disallowed for public clients
	not client_registration.allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		"token_endpoint_auth_method": "none",
		"client_uri": "https://example.com/",
	}
}

test_is_subdomain if {
	client_registration.is_subdomain("example.com", "example.com")
	client_registration.is_subdomain("example.com", "app.example.com")
	not client_registration.is_subdomain("example.com", "example.org")
	not client_registration.is_subdomain("test.com", "example.com")
}

test_reverse_dns_match if {
	client_registration.reverse_dns_match("example.com", "com.example")
	client_registration.reverse_dns_match("example.com", "com.example.app")
	not client_registration.reverse_dns_match("example.com", "org.example")
	not client_registration.reverse_dns_match("test.com", "com.example")
}

test_parse_uri if {
	client_uri_query := client_registration.parse_uri("https://example.com:8080/users?query=test")
	client_uri_query.authority == "example.com:8080"
	client_uri_query.host == "example.com"
	client_uri_query.path == "/users"
	client_uri_query.scheme == "https"
	client_uri_query.port == "8080"
	client_uri_query.query == "?query=test"
}
