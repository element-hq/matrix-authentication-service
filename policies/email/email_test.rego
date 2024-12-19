package email_test

import data.email
import rego.v1

test_allow_all_domains if {
	email.allow with input.email as "hello@staging.element.io"
}

test_allowed_domain if {
	email.allow with input.email as "hello@staging.element.io"
		with data.allowed_domains as ["*.element.io"]
}

test_not_allowed_domain if {
	not email.allow with input.email as "hello@staging.element.io"
		with data.allowed_domains as ["example.com"]
}

test_banned_domain if {
	not email.allow with input.email as "hello@staging.element.io"
		with data.banned_domains as ["*.element.io"]
}

test_banned_subdomain if {
	not email.allow with input.email as "hello@staging.element.io"
		with data.allowed_domains as ["*.element.io"]
		with data.banned_domains as ["staging.element.io"]
}
