package com.scality.keycloak.truststore;

import org.keycloak.provider.Spi;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;

public class CertificateTruststoreSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "userAddress";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return CertificateTruststoreProvider.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return CertificateTruststoreProviderFactory.class;
    }
}
