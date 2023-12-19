package com.scality.keycloak.truststore;

import java.util.stream.Stream;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class TruststoreAdminResource {
    protected static final Logger logger = Logger.getLogger(TruststoreAdminResource.class);
    protected final AdminPermissionEvaluator auth;
    protected final KeycloakSession session;

    public TruststoreAdminResource(KeycloakSession session, AdminPermissionEvaluator auth) {
        this.session = session;
        this.auth = auth;
    }

    private final String OPEN_API_TAG = "Truststore Admin API";

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Get certificates Returns a list of trusted certificates.")
    public Stream<CertificateRepresentation> getCertificates() {
        auth.realm().requireManageRealm();

        logger.info("getCertificates");

        return Stream.of(new CertificateRepresentation());
    }

}
