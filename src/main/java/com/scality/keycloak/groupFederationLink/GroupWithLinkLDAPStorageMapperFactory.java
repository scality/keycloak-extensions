package com.scality.keycloak.groupFederationLink;

import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapperFactory;

import jakarta.persistence.EntityManager;

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

    @Override
    public void preRemove(KeycloakSession session, RealmModel realm, ComponentModel model) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<GroupFederationLinkEntity> links = em
                .createNamedQuery("findByFederationLink", GroupFederationLinkEntity.class)
                .setParameter("federationLink", model.getId())
                .getResultList();
        for (GroupFederationLinkEntity link : links) {
            GroupModel group = realm.getGroupById(link.getGroupId());
            if (group != null) {
                realm.removeGroup(group);
            }
        }
    }

}
