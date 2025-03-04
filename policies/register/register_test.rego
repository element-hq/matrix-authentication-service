package register_test

import data.register
import rego.v1

mock_registration := {
	"registration_method": "password",
	"username": "hello",
	"email": "hello@staging.element.io",
}

test_allow_all_domains if {
	register.allow with input as mock_registration
}

test_allowed_domain if {
	register.allow with input as mock_registration
		with data.allowed_domains as ["*.element.io"]
}

test_not_allowed_domain if {
	not register.allow with input as mock_registration
		with data.allowed_domains as ["example.com"]
}

test_banned_domain if {
	not register.allow with input as mock_registration
		with data.banned_domains as ["*.element.io"]
}

test_banned_subdomain if {
	not register.allow with input as mock_registration
		with data.allowed_domains as ["*.element.io"]
		with data.banned_domains as ["staging.element.io"]
}

test_email_required if {
	not register.allow with input as {"username": "hello", "registration_method": "password"}
}

test_no_email if {
	register.allow with input as {"username": "hello", "registration_method": "upstream-oauth2"}
}

test_empty_username if {
	not register.allow with input as {"username": "", "registration_method": "upstream-oauth2"}
}

test_long_username if {
	not register.allow with input as {
		"username": concat("", ["a" | some x in numbers.range(1, 249)]),
		"registration_method": "upstream-oauth2",
	}
		with data.server_name as "matrix.org"

	# This makes a MXID that is exactly 255 characters long
	register.allow with input as {
		"username": concat("", ["a" | some x in numbers.range(1, 249)]),
		"registration_method": "upstream-oauth2",
	}
		with data.server_name as "a.io"

	not register.allow with input as {
		"username": concat("", ["a" | some x in numbers.range(1, 250)]),
		"registration_method": "upstream-oauth2",
	}
		with data.server_name as "a.io"
}

test_invalid_username if {
	not register.allow with input as {"username": "hello world", "registration_method": "upstream-oauth2"}
}

test_numeric_username if {
	not register.allow with input as {"username": "1234", "registration_method": "upstream-oauth2"}
}

test_allowed_username if {
	register.allow with input as {"username": "hello", "registration_method": "upstream-oauth2"}
		with data.registration.allowed_usernames.literals as ["hello"]
	not register.allow with input as {"username": "hello", "registration_method": "upstream-oauth2"}
		with data.registration.allowed_usernames.literals as ["world"]
}

test_banned_username if {
	not register.allow with input as {"username": "hello", "registration_method": "upstream-oauth2"}
		with data.registration.banned_usernames.literals as ["hello"]
	register.allow with input as {"username": "hello", "registration_method": "upstream-oauth2"}
		with data.registration.banned_usernames.literals as ["world"]
}

test_ip_ban if {
	not register.allow with input as {
		"username": "hello",
		"registration_method": "upstream-oauth2",
		"requester": {"ip_address": "1.1.1.1"},
	}
		with data.requester.banned_ips as ["1.1.1.1"]

	not register.allow with input as {
		"username": "hello",
		"registration_method": "upstream-oauth2",
		"requester": {"ip_address": "1.1.1.1"},
	}
		with data.requester.banned_ips as ["1.0.0.0/8"]

	not register.allow with input as {
		"username": "hello",
		"registration_method": "upstream-oauth2",
		"requester": {"user_agent": "Evil Client"},
	}
		with data.requester.banned_user_agents.substrings as ["Evil"]
}
