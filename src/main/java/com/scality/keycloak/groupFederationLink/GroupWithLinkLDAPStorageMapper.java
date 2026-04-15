package com.scality.keycloak.groupFederationLink;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapperFactory;
import org.keycloak.storage.user.SynchronizationResult;

import jakarta.persistence.EntityManager;

public class GroupWithLinkLDAPStorageMapper extends GroupLDAPStorageMapper {

    private final List<GroupFederationLinkEntity> pendingLinks = new ArrayList<>();

    public GroupWithLinkLDAPStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider,
            GroupLDAPStorageMapperFactory factory) {
        super(mapperModel, ldapProvider, factory);
    }

    private EntityManager getEntityManager() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    @Override
    public SynchronizationResult syncDataFromFederationProviderToKeycloak(RealmModel realm) {
        pendingLinks.clear();
        SynchronizationResult result = super.syncDataFromFederationProviderToKeycloak(realm);

        if (!pendingLinks.isEmpty()) {
            EntityManager em = getEntityManager();
            for (GroupFederationLinkEntity entity : pendingLinks) {
                em.persist(entity);
            }
            em.flush();
            pendingLinks.clear();
        }

        return result;
    }

    @Override
    protected GroupModel createKcGroup(RealmModel realm, String ldapGroupName, GroupModel parentGroup) {
        GroupModel groupModel = super.createKcGroup(realm, ldapGroupName, parentGroup);

        GroupFederationLinkEntity entity = new GroupFederationLinkEntity();
        entity.setGroupId(groupModel.getId());
        entity.setFederationLink(ldapProvider.getModel().getId());
        pendingLinks.add(entity);

        return groupModel;
    }

}
