package com.scality.keycloak.truststore;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class JpaCertificateTruststoreProviderFactory implements CertificateTruststoreProviderFactory {

    @Override
    public CertificateTruststoreProvider create(KeycloakSession session) {
        return new JpaCertificateTruststoreProvider(session);
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "JpaUserAddressProvider";
    }

}
