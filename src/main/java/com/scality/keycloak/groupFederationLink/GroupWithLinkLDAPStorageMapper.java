package com.scality.keycloak.groupFederationLink;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.membership.group.GroupLDAPStorageMapperFactory;
import org.keycloak.storage.user.SynchronizationResult;

import jakarta.persistence.EntityManager;

public class GroupWithLinkLDAPStorageMapper extends GroupLDAPStorageMapper {

    private final Map<String, GroupFederationLinkEntity> pendingLinks = new LinkedHashMap<>();

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
        stagePendingLinksForAllLDAPGroups(realm);

        if (!pendingLinks.isEmpty()) {
            EntityManager em = getEntityManager();
            for (GroupFederationLinkEntity entity : pendingLinks.values()) {
                if (em.find(GroupFederationLinkEntity.class, entity.getGroupId()) == null) {
                    em.persist(entity);
                }
            }
            em.flush();
            pendingLinks.clear();
        }

        return result;
    }

    @Override
    protected GroupModel createKcGroup(RealmModel realm, String ldapGroupName, GroupModel parentGroup) {
        GroupModel groupModel = super.createKcGroup(realm, ldapGroupName, parentGroup);
        stagePendingLink(groupModel);
        return groupModel;
    }

    // Parent's sync only calls createKcGroup for brand-new groups; existing KC groups
    // that match by name go through a private update path we can't hook. Reconcile
    // here so every LDAP group ends up with a federation link, whether created now
    // or matched to a pre-existing local group.
    private void stagePendingLinksForAllLDAPGroups(RealmModel realm) {
        List<LDAPObject> ldapGroups = getAllLDAPGroups(false);
        for (LDAPObject ldapGroup : ldapGroups) {
            GroupModel kcGroup = findKcGroupByLDAPGroup(realm, null, ldapGroup);
            if (kcGroup != null) {
                stagePendingLink(kcGroup);
            }
        }
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
