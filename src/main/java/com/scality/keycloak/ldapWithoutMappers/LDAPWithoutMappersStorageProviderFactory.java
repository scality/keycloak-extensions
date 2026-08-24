package com.scality.keycloak.ldapWithoutMappers;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;

public class LDAPWithoutMappersStorageProviderFactory extends LDAPStorageProviderFactory {

    // Bounded LDAP socket timeouts (milliseconds) injected when the wizard leaves them empty.
    // Kept well under the RING reverse proxy's ~60s read timeout so an LDAP outage fails fast
    // enough for LdapAwareUsernamePasswordForm to render a generic error, rather than hanging
    // until the proxy returns a 502. See RING-54200.
    private static final String DEFAULT_CONNECTION_TIMEOUT_MS = "5000";
    private static final String DEFAULT_READ_TIMEOUT_MS = "10000";

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        // We intentionnaly do not call super.onCreate() to avoid the creation of the
        // default mappers
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) {
        if (isBlank(config.getConfig().getFirst("connectionTimeout"))) {
            config.getConfig().putSingle("connectionTimeout", DEFAULT_CONNECTION_TIMEOUT_MS);
        }
        if (isBlank(config.getConfig().getFirst("readTimeout"))) {
            config.getConfig().putSingle("readTimeout", DEFAULT_READ_TIMEOUT_MS);
        }
        super.validateConfiguration(session, realm, config);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isEmpty();
    }

    @Override
    public String getId() {
        return "ldap-without-mappers";
    }

}
