package com.scality.keycloak.groupFederationLink;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

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
    // connection closed (Agroal "Closing open connection(s) prior to commit"), which
    // also rules out calling super.findKcGroupByLDAPGroup (it runs on that session).
    private void reconcileAndPersistLinks(KeycloakSession innerSession, String realmId) {
        RealmModel innerRealm = innerSession.realms().getRealm(realmId);
        EntityManager em = innerSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        GroupMapperConfig config = new GroupMapperConfig(mapperModel);

        GroupModel groupsPathGroup = config.isTopLevelGroupsPath() ? null
                : KeycloakModelUtils.findGroupByPath(innerSession, innerRealm, config.getGroupsPath());

        for (LDAPObject ldapGroup : getAllLDAPGroups(false)) {
            String groupName = ldapGroup.getAttributeAsString(config.getGroupNameLdapAttribute());
            GroupModel kcGroup = findKcGroup(innerSession, innerRealm, config, groupsPathGroup, groupName);
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

    // Mirrors GroupLDAPStorageMapper.findKcGroupByLDAPGroup, but resolved against the
    // fresh session: match anywhere under the groups path when inheritance is preserved,
    // otherwise a direct child of it.
    private GroupModel findKcGroup(KeycloakSession session, RealmModel realm, GroupMapperConfig config,
            GroupModel groupsPathGroup, String groupName) {
        if (config.isPreserveGroupsInheritance()) {
            return allKcGroupsUnder(realm, groupsPathGroup)
                    .filter(group -> Objects.equals(group.getName(), groupName))
                    .findFirst()
                    .orElse(null);
        }
        return session.groups().getGroupByName(realm, groupsPathGroup, groupName);
    }

    private static Stream<GroupModel> allKcGroupsUnder(RealmModel realm, GroupModel topParentGroup) {
        Stream<GroupModel> allGroups = realm.getGroupsStream();
        if (topParentGroup == null) {
            return allGroups;
        }
        return allGroups.filter(group -> {
            GroupModel parent = group.getParent();
            while (parent != null) {
                if (parent.getId().equals(topParentGroup.getId())) {
                    return true;
                }
                parent = parent.getParent();
            }
            return false;
        });
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
