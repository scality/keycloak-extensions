package com.scality.keycloak.groupFederationLink;

import static org.keycloak.models.jpa.PaginationUtils.paginateQuery;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.GroupsResource;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.GroupPermissionEvaluator;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class GroupWithLinkAdminResource {
    protected static final Logger logger = Logger.getLogger(GroupWithLinkAdminResource.class);
    protected final AdminPermissionEvaluator auth;
    protected final KeycloakSession session;
    private GroupsResource groupsResource;

    public GroupWithLinkAdminResource(KeycloakSession session, AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        this.groupsResource = new GroupsResource(session.getContext().getRealm(), session, auth,
                adminEvent.resource(ResourceType.GROUP));
        this.session = session;
        this.auth = auth;
    }

    /***
     * 
     * @return EntityManager
     */
    private EntityManager getEntityManager() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.GROUPS)
    @Operation(summary = "Get groups")
    public Stream<GroupWithLinkRepresentation> getGroupsWithLink(@QueryParam("search") String search,
            @QueryParam("link") String federationLink,
            @QueryParam("exact") @DefaultValue("false") Boolean exact,
            @QueryParam("first") Integer firstResult,
            @QueryParam("max") Integer maxResults) {

        GroupPermissionEvaluator groupsEvaluator = auth.groups();
        groupsEvaluator.requireList();
        logger.info("getGroupsWithLink");

        if (Objects.isNull(federationLink) || federationLink.isEmpty()) {
            Stream<GroupRepresentation> groups = groupsResource.getGroups(search, null, exact, firstResult,
                    maxResults, true, true);

            return groups.map(group -> {
                GroupWithLinkRepresentation groupWithLink = new GroupWithLinkRepresentation();
                groupWithLink.setId(group.getId());
                groupWithLink.setName(group.getName());
                groupWithLink.setPath(group.getPath());
                groupWithLink.setParentId(group.getParentId());
                groupWithLink.setSubGroupCount(group.getSubGroupCount());
                groupWithLink.setSubGroups(group.getSubGroups());
                groupWithLink.setAttributes(group.getAttributes());
                groupWithLink.setRealmRoles(group.getRealmRoles());
                groupWithLink.setClientRoles(group.getClientRoles());

                try {
                    GroupFederationLinkEntity groupFederationLinkEntity = getEntityManager()
                            .createNamedQuery("findByGroupId", GroupFederationLinkEntity.class)
                            .setParameter("groupId", group.getId())
                            .getSingleResult();
                    groupWithLink.setFederationLink(groupFederationLinkEntity.getFederationLink());
                } catch (NoResultException e) {
                    logger.trace("No federation link found for group " + group.getId(), e);
                }

                return groupWithLink;
            });
        }

        try {
            TypedQuery<GroupEntity> query = getEntityManager()
                    .createNamedQuery("findGroupsByFederationLinkAndName", GroupEntity.class)
                    .setParameter("federationLink", federationLink)
                    .setParameter("name", search);
            if (Objects.isNull(search) || search.isEmpty()) {
                query = getEntityManager()
                        .createNamedQuery("findGroupsByFederationLink", GroupEntity.class)
                        .setParameter("federationLink", federationLink);
            }

            List<GroupEntity> resultList = paginateQuery(query, firstResult, maxResults).getResultList();
            return resultList.stream().map(groupEntity -> {
                GroupWithLinkRepresentation groupFederationLinkEntity = new GroupWithLinkRepresentation();
                groupFederationLinkEntity.setId(groupEntity.getId());
                groupFederationLinkEntity.setName(groupEntity.getName());
                groupFederationLinkEntity.setParentId(groupEntity.getParentId());
                groupFederationLinkEntity.setFederationLink(federationLink);
                return groupFederationLinkEntity;
            });
        } catch (NoResultException e) {
            logger.trace("No group found for federation link " + federationLink, e);
            return Stream.empty();
        }
    }

    @GET
    @Path("count")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.GROUPS)
    @Operation(summary = "Get groups")
    public Map<String, Long> countGroupsWithLink(@QueryParam("search") String search,
            @QueryParam("link") String federationLink) {

        GroupPermissionEvaluator groupsEvaluator = auth.groups();
        groupsEvaluator.requireList();
        logger.info("getGroupsWithLink");

        if (Objects.isNull(federationLink) || federationLink.isEmpty()) {
            Map<String, Long> count = groupsResource.getGroupCount(search, false);

            return count;
        }

        try {
            TypedQuery<Long> query = getEntityManager()
                    .createNamedQuery("countGroupsByFederationLinkAndName", Long.class)
                    .setParameter("federationLink", federationLink)
                    .setParameter("name", search);
            if (Objects.isNull(search) || search.isEmpty()) {
                query = getEntityManager()
                        .createNamedQuery("countGroupsByFederationLink", Long.class)
                        .setParameter("federationLink", federationLink);
            }

            Long count = query.getSingleResult();
            Map<String, Long> result = new HashMap<>();
            result.put("count", count);
            return result;
        } catch (NoResultException e) {
            logger.trace("No group found for federation link " + federationLink, e);
            Map<String, Long> result = new HashMap<>();
            result.put("count", 0L);
            return result;
        }
    }

}
