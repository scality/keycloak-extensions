package com.scality.keycloak.truststore;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.quarkus.runtime.integration.QuarkusKeycloakSessionFactory;
import org.keycloak.truststore.TruststoreProvider;
import org.keycloak.truststore.TruststoreProviderFactory;

public class DBTruststoreProviderFactory implements TruststoreProviderFactory {

    private TruststoreProvider provider;

    @Override
    public TruststoreProvider create(KeycloakSession session) {
        return provider;
    }

    @Override
    public void init(Scope config) {
        // Noop
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Noop
        KeycloakSession session = factory.create();
        provider = new DBTruststoreProvider(session);
        TruststoreProviderSingleton.set(provider);
    }

    @Override
    public void close() {
        // Nothing to close
    }

    @Override
    public String getId() {
        return "file";
    }

    @Override
    public int order() {
        return 1;
    }

}
