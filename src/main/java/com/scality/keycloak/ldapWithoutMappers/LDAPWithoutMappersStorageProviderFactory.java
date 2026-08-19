package com.scality.keycloak.ldapWithoutMappers;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;

public class LDAPWithoutMappersStorageProviderFactory extends LDAPStorageProviderFactory {

    private static final String DEFAULT_CONNECTION_TIMEOUT_MS = "5000";
    private static final String DEFAULT_READ_TIMEOUT_MS = "10000";

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        // We intentionnaly do not call super.onCreate() to avoid the creation of the
        // default mappers
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) {
        String connectionTimeout = config.get(LDAPConstants.CONNECTION_TIMEOUT);
        if (connectionTimeout == null || connectionTimeout.isEmpty()) {
            config.put(LDAPConstants.CONNECTION_TIMEOUT, DEFAULT_CONNECTION_TIMEOUT_MS);
        }

        String readTimeout = config.get(LDAPConstants.READ_TIMEOUT);
        if (readTimeout == null || readTimeout.isEmpty()) {
            config.put(LDAPConstants.READ_TIMEOUT, DEFAULT_READ_TIMEOUT_MS);
        }

        super.validateConfiguration(session, realm, config);
    }

    @Override
    public String getId() {
        return "ldap-without-mappers";
    }

}
