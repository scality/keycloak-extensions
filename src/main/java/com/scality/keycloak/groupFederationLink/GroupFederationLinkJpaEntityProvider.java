package com.scality.keycloak.groupFederationLink;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import java.util.Collections;
import java.util.List;

public class GroupFederationLinkJpaEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        return Collections.<Class<?>>singletonList(GroupFederationLinkEntity.class);
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/group-federation-changelog.xml";
    }

    @Override
    public String getFactoryId() {
        return GroupFederationLinkJpaEntityProviderFactory.ID;
    }

    @Override
    public void close() {
    }

}
