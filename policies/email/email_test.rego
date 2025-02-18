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

test_regex_banned if {
	not email.allow with input.email as "hello@staging.element.io"
		with data.emails.banned_addresses.regexes as ["hello@.*"]
}

test_literal_banned if {
	not email.allow with input.email as "hello@staging.element.io"
		with data.emails.banned_addresses.literals as ["hello@staging.element.io"]
}

test_regex_allowed if {
	email.allow with input.email as "hello@staging.element.io"
		with data.emails.allowed_addresses.regexes as ["hello@.*"]
	not email.allow with input.email as "hello@staging.element.io"
		with data.emails.allowed_addresses.regexes as ["hola@.*"]
}

test_literal_allowed if {
	email.allow with input.email as "hello@staging.element.io"
		with data.emails.allowed_addresses.literals as ["hello@staging.element.io"]
	not email.allow with input.email as "hello@staging.element.io"
		with data.emails.allowed_addresses.literals as ["hola@staging.element.io"]
}
