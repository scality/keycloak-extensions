package com.scality.keycloak.truststore;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import java.util.Collections;
import java.util.List;

public class TrustoreJpaEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        return Collections.<Class<?>>singletonList(TruststoreEntity.class);
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/trustore-changelog.xml";
    }

    @Override
    public String getFactoryId() {
        return TruststoreJpaEntityProviderFactory.ID;
    }

    @Override
    public void close() {
    }

}
