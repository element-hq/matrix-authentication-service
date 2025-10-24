# `templates`

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `templates check`

Check the validity of the templates loaded by the config.
It compiles the templates and then renders them with different contexts.

```console
$ mas-cli templates check
INFO mas_core::templates: Loading templates from filesystem path=./templates/**/*.{html,txt}
INFO mas_core::templates::check: Rendering template name="login.html" context={"csrf_token":"fake_csrf_token","form":{"fields_errors":{},"form_errors":[],"has_errors":false}}
INFO mas_core::templates::check: Rendering template name="register.html" context={"__UNUSED":null,"csrf_token":"fake_csrf_token"}
INFO mas_core::templates::check: Rendering template name="index.html" context={"csrf_token":"fake_csrf_token","current_session":{"active":true,"created_at":"2021-09-24T13:26:52.962135085Z","id":1,"last_authd_at":"2021-09-24T13:26:52.962135316Z","user_id":2,"username":"john"},"discovery_url":"https://example.com/.well-known/openid-configuration"}
...
```

What is checked:
- the Jinja templates are syntactically valid
- all translation keys exist

What is not checked:
- the validity of the generated HTML (you can forget closing tags, or otherwise create invalid HTML output)
- undefined variables (`{{ undefined_variable }}` will render as an empty string and not raise an error)
- all translation keys exist *in your intended language(s)* (so some translation keys may fall back to English)
