# Policy engine

A set of actions are controlled by a generic policy engine.
A decision of the policy engine is deterministically made based on three components:

 - The policy itself
 - A static configuration
 - The action to be performed

The policy is a [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) policy compiled into WebAssembly.
Matrix Authentication Service ships with a default policy which should be sufficient for most deployments.
It can be replaced with a custom policy if needed, which can be useful to implement custom authorization logic without recompiling the service.

## Actions

The policy engine mainly restricts three operations:

 - **User attributes**, which includes user registration, user profile updates, and user password changes.
 - **Client registration**, when an OAuth 2.0 dynamic client registration is requested.
 - **Authorization requests**, when a client requests an access token.

Policies are only evaluated in user-facing contexts, and not in administrative contexts.
As such, they usually can be bypassed through the admin API or the CLI if needed.

### User attributes

The policy is evaluated in the following different scenarios:

 - [`register.rego`]: During user registration, either with password credentials or with an upstream OAuth 2.0 provider. This calls the [`email.rego`] policy as well.
 - [`email.rego`]: When a user adds a new email address to their account.

### Client registration

The policy ([`client_registration.rego`]) is evaluated when a client sends their metadata through the OAuth 2.0 dynamic client registration API.
By default, it enforces a set of strict rules to make sure clients provide enough information about themselves, with coherent URLs.
This is useful in production environments, but can be relaxed in development environments.

### Authorization requests

The policy ([`authorization_grant.rego`]) is evaluated when a client requests an access token.
This only covers OAuth 2.0 sessions, not compatibility sessions.
It is evaluated for the authorization code grant, the client credentials grant and the device authorization grant.

This is probably the most interesting policy, as it defines which scope can be granted to which user and which client.

On evaluation, three main entities are available:

 - details about **the grant**, such as the type of grant and the requested scopes
 - **the client** making the request
 - **the user** with their attributes (only for the authorization code grant and the device authorization grant)

The policy evaluation cannot *modify* the grant, only allow or deny it.
Therefore the client must know in advance which scope they want to request.

This is an important concept to understand: what access a token has is stored in the session itself, therefore access to privileged scopes is only based on policy evaluation, not on user attributes.

If we take the Synapse admin API access as an example, the fact that an access token has admin API access doesn't depend on attributes on the user *directly*.
Instead, it is during the creation of the session that:

 - the client asks for the corresponding scope (e.g. `urn:synapse:admin:*`)
 - the policy engine decides whether to grant it or not

The default policy shipped with the service does gate access to this scope based on a user attributes (`can_request_admin`), but this is not a requirement.

It does make reasoning about admin access more complicated compared to a simple boolean flag on the user like what Synapse does, but it also allows for more complex authorization logic.
This is especially important as in the future it will make it possible to implement a more granular role-based access control system to fit more complex use cases.

To understand the authorization process and how sessions are created, refer to the [authorization and sessions](./authorization.md) section.


[`register.rego`]: https://github.com/element-hq/matrix-authentication-service/blob/main/policies/register/register.rego 
[`email.rego`]: https://github.com/element-hq/matrix-authentication-service/blob/main/policies/email/email.rego 
[`client_registration.rego`]: https://github.com/element-hq/matrix-authentication-service/blob/main/policies/client_registration/client_registration.rego 
[`authorization_grant.rego`]: https://github.com/element-hq/matrix-authentication-service/blob/main/policies/authorization_grant/authorization_grant.rego
