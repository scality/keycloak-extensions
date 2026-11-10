# Scality Keycloak Extensions

## Hostname provider based on the request

We set the default hsotname provider back to the one from Keycloak versions prior to the 20th.
This hostname provider define the hostname based on the incoming authentication request and then enables us to deploy the same keycloak for different network planes.


## Truststore Provider and SPI

We built an extension to keyclaok Admin API that allows keycloak Admins to upload CA certificates to trust.
This enables full API driven integration with external providers (such as LDAP over TLS using STARTTLS, or SMTP using STARTTLS).
It removes the needs of updating the truststore and having to restart keycloak services.


## Long-lived tokens

An admin can issue an access token for the service account of a client with a lifespan of up to a year, for tools that cannot renew a token:
`POST /admin/realms/{realm}/long-lived-tokens/clients/{client-uuid}` with `{"lifespan": "30d", "label": "..."}`.
The token is returned once and recorded in the `LONG_LIVED_TOKEN` registry.

Each token is signed with a key pair of its own, whose key id is the token's `jti`. The private key is dropped once the token is signed. The public key is published in the realm JWKS by the `long-lived-tokens` key provider (*Realm settings → Keys*), which Keycloak creates on the first issuance.

- `POST /admin/realms/{realm}/long-lived-tokens/{jti}/revoke` revokes a token: its key leaves the JWKS, so Keycloak refuses it at once. A verifier that cached the JWKS keeps accepting it until it fetches the JWKS again.
- `GET /admin/realms/{realm}/long-lived-tokens/clients/{client-uuid}` lists a client's tokens, never the tokens themselves, and `DELETE /admin/realms/{realm}/long-lived-tokens/{jti}` removes an expired one from the registry.
- A realm holds at most 20 active (neither revoked nor expired) long-lived tokens, since every client of the realm downloads their keys, and a client at most 2, enough to rotate: issue the next token, switch to it, then revoke the old one. Set `spi-admin-realm-restapi-extension--long-lived-tokens--max-active-tokens` and `spi-admin-realm-restapi-extension--long-lived-tokens--max-active-tokens-per-client` to change them. Issuing beyond a limit answers 409.
- A rotation of the realm keys does not affect long-lived tokens.
- Disabling the `long-lived-tokens` key provider makes every long-lived token of the realm unverifiable until it is enabled again. Use it as an emergency switch only. A deleted provider is created again on the next issuance, and the tokens come back with it.
- The client must sign its access tokens with an asymmetric algorithm (RS, PS or ES). A client set to HS256 cannot get one.
