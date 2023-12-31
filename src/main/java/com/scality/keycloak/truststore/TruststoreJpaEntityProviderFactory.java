package com.scality.keycloak.truststore;

import org.keycloak.Config.Scope;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class TruststoreJpaEntityProviderFactory implements JpaEntityProviderFactory {
    protected static final String ID = "truststore-entity-provider";

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return new TrustoreJpaEntityProvider();
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
        return ID;
    }

}
