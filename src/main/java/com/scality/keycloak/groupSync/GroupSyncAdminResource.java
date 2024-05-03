package com.scality.keycloak.groupSync;

import java.util.HashMap;

import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.UserStorageProviderResource;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.user.SynchronizationResult;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class GroupSyncAdminResource {
    protected static final Logger logger = Logger.getLogger(GroupSyncAdminResource.class);
    protected final AdminPermissionEvaluator auth;
    protected final KeycloakSession session;
    protected final RealmModel realm;

    public GroupSyncAdminResource(KeycloakSession session, AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        this.session = session;
        this.auth = auth;
        this.realm = session.getContext().getRealm();
    }

    /**
     * Trigger sync of mapper data related to ldap mapper (roles, groups, ...)
     *
     * direction is "fedToKeycloak" or "keycloakToFed"
     *
     * @return
     */
    @POST
    @Path("{parentId}/mappers/{id}/sync")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public SynchronizationResult syncMapperData(@PathParam("parentId") String parentId,
            @PathParam("id") String mapperId, @QueryParam("direction") String direction) {
        auth.users().requireManage();

        ComponentModel parentModel = realm.getComponent(parentId);
        if (parentModel == null)
            throw new NotFoundException("Parent model not found");
        ComponentModel mapperModel = realm.getComponent(mapperId);
        if (mapperModel == null)
            throw new NotFoundException("Mapper model not found");

        LDAPStorageProvider ldapProvider = (LDAPStorageProvider) session.getProvider(UserStorageProvider.class,
                parentModel);
        LDAPStorageMapper mapper = session.getProvider(LDAPStorageMapper.class, mapperModel);

        ServicesLogger.LOGGER.syncingDataForMapper(mapperModel.getName(), mapperModel.getProviderId(), direction);

        SynchronizationResult syncResult;
        if ("fedToKeycloak".equals(direction)) {
            try {
                syncResult = mapper.syncDataFromFederationProviderToKeycloak(realm);
            } catch (Exception e) {
                String errorMsg = UserStorageProviderResource.getErrorCode(e);
                throw ErrorResponse.error(errorMsg, Response.Status.BAD_REQUEST);
            }
        } else if ("keycloakToFed".equals(direction)) {
            try {
                syncResult = mapper.syncDataFromKeycloakToFederationProvider(realm);
            } catch (Exception e) {
                String errorMsg = UserStorageProviderResource.getErrorCode(e);
                throw ErrorResponse.error(errorMsg, Response.Status.BAD_REQUEST);
            }
        } else {
            throw new BadRequestException("Unknown direction: " + direction);
        }

        return syncResult;
    }
}
