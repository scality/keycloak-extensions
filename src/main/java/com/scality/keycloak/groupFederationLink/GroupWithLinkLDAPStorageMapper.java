package com.scality.keycloak.groupFederationLink;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.membership.group.GroupMapperConfig;
import org.keycloak.storage.user.SynchronizationResult;

import jakarta.persistence.EntityManager;

public class GroupWithLinkLDAPStorageMapper extends GroupLDAPStorageMapper {

    private final Map<String, GroupFederationLinkEntity> pendingLinks = new LinkedHashMap<>();

    public GroupWithLinkLDAPStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider,
            GroupLDAPStorageMapperFactory factory) {
        super(mapperModel, ldapProvider, factory);
    }

    @Override
    public SynchronizationResult syncDataFromFederationProviderToKeycloak(RealmModel realm) {
        pendingLinks.clear();
        SynchronizationResult result = super.syncDataFromFederationProviderToKeycloak(realm);

        KeycloakModelUtils.runJobInTransaction(
                ldapProvider.getSession().getKeycloakSessionFactory(),
                innerSession -> reconcileAndPersistLinks(innerSession, realm.getId()));
        pendingLinks.clear();

        return result;
    }

    @Override
    protected GroupModel createKcGroup(RealmModel realm, String ldapGroupName, GroupModel parentGroup) {
        GroupModel groupModel = super.createKcGroup(realm, ldapGroupName, parentGroup);
        stagePendingLink(groupModel);
        return groupModel;
    }

    // super's sync links only groups it creates; groups matched to existing KC groups
    // by name are skipped, so reconcile a link for every LDAP group here. Must use a
    // fresh session: super's inner transactions leave the outer session's JDBC
    // connection closed (Agroal "Closing open connection(s) prior to commit").
    private void reconcileAndPersistLinks(KeycloakSession innerSession, String realmId) {
        RealmModel innerRealm = innerSession.realms().getRealm(realmId);
        EntityManager em = innerSession.getProvider(JpaConnectionProvider.class).getEntityManager();

        String groupNameAttr = mapperModel.getConfig()
                .getFirst(GroupMapperConfig.GROUP_NAME_LDAP_ATTRIBUTE);
        List<LDAPObject> ldapGroups = getAllLDAPGroups(false);
        for (LDAPObject ldapGroup : ldapGroups) {
            String groupName = ldapGroup.getAttributeAsString(groupNameAttr);
            GroupModel kcGroup = innerSession.groups().getGroupByName(innerRealm, null, groupName);
            if (kcGroup != null) {
                stagePendingLink(kcGroup);
            }
        }

        for (GroupFederationLinkEntity entity : pendingLinks.values()) {
            if (em.find(GroupFederationLinkEntity.class, entity.getGroupId()) == null) {
                em.persist(entity);
            }
        }
        em.flush();
    }

    private void stagePendingLink(GroupModel groupModel) {
        String groupId = groupModel.getId();
        if (pendingLinks.containsKey(groupId)) {
            return;
        }
        GroupFederationLinkEntity entity = new GroupFederationLinkEntity();
        entity.setGroupId(groupId);
        entity.setFederationLink(ldapProvider.getModel().getId());
        pendingLinks.put(groupId, entity);
    }

}
