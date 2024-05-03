package com.scality.keycloak.groupFederationLink;

import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapperFactory;

import jakarta.persistence.EntityManager;

public class GroupWithLinkLDAPStorageMapper extends GroupLDAPStorageMapper {

    public GroupWithLinkLDAPStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider,
            GroupLDAPStorageMapperFactory factory) {
        super(mapperModel, ldapProvider, factory);
    }

    /***
     * 
     * @return EntityManager
     */
    private EntityManager getEntityManager() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    @Override
    protected GroupModel createKcGroup(RealmModel realm, String ldapGroupName, GroupModel parentGroup) {
        GroupModel groupModel = super.createKcGroup(realm, ldapGroupName, parentGroup);

        EntityManager em = getEntityManager();
        GroupFederationLinkEntity groupFederationLinkEntity = new GroupFederationLinkEntity();
        groupFederationLinkEntity.setGroupId(groupModel.getId());
        groupFederationLinkEntity.setFederationLink(ldapProvider.getModel().getId());
        em.persist(groupFederationLinkEntity);
        em.flush();

        return groupModel;
    }

}
