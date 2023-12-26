# Scality Keycloak Extensions

## Hostname provider based on the request

We set the default hsotname provider back to the one from Keycloak versions prior to the 20th.
This hostname provider define the hostname based on the incoming authentication request and then enables us to deploy the same keycloak for different network planes.


## Truststore Provider and SPI

We built an extension to keyclaok Admin API that allows keycloak Admins to upload CA certificates to trust.
This enables full API driven integration with external providers (such as LDAP over TLS using STARTTLS, or SMTP using STARTTLS).
It removes the needs of updating the truststore and having to restart keycloak services.
