package com.scality.keycloak.longLivedToken;

import java.util.Collections;
import java.util.List;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

public class LongLivedTokenJpaEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        return Collections.<Class<?>>singletonList(LongLivedTokenEntity.class);
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/long-lived-token-changelog.xml";
    }

    @Override
    public String getFactoryId() {
        return LongLivedTokenJpaEntityProviderFactory.ID;
    }

    @Override
    public void close() {
    }

}
