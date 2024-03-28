package com.scality.keycloak.groupFederationLink;

import org.keycloak.component.ComponentModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapperFactory;

public class GroupWithLinkLDAPStorageMapperFactory extends GroupLDAPStorageMapperFactory {
    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel,
            LDAPStorageProvider federationProvider) {
        return new GroupWithLinkLDAPStorageMapper(mapperModel, federationProvider, this);
    }

    @Override
    public String getId() {
        return "group-with-link-ldap-mapper";
    }

}
