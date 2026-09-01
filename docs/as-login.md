# About Application Services login

Encrypted Application Services/Bridges currently leverage the `m.login.application_service` login type to create devices for users.
This API is *not* available in the Matrix Authentication Service: as per [Matrix 1.19](https://spec.matrix.org/v1.19/application-service-api/#registration), calling `/login` with this login type returns a 400 HTTP status code with an `M_APPSERVICE_LOGIN_UNSUPPORTED` error code.

We're working on a solution to support this use case, but in the meantime, this means **encrypted bridges will not work with the Matrix Authentication Service.**
A workaround is to disable E2EE support in your bridge setup.
