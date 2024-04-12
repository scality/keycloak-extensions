package com.scality.keycloak.ldapWithoutMappers;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;

public class LDAPWithoutMappersStorageProviderFactory extends LDAPStorageProviderFactory {

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        // We intentionnaly do not call super.onCreate() to avoid the creation of the
        // default mappers
    }

    @Override
    public String getId() {
        return "ldap-without-mappers";
    }

}
