package com.scality.keycloak.truststore;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
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

        return Stream.of(session.getProvider(CertificateTruststoreProvider.class).getCertificates());
    }

    @POST
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Add certificate Adds a trusted certificate.")
    public void addCertificate(CertificateRepresentation certificate) throws CertificateException {
        auth.realm().requireManageRealm();

        CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
        try {
            if (provider.getCertificate(certificate.alias()) != null) {
                throw new ClientErrorException("Certificate already exists", 409);
            }
        } catch (NotFoundException e) {
            // ignore
        }

        provider.addCertificate(certificate.alias(),
                certificate.certificate());
    }

    @Path("{alias}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Get certificate Returns a trusted certificate.")
    public CertificateRepresentation getCertificate(String alias) {
        auth.realm().requireManageRealm();

        return session.getProvider(CertificateTruststoreProvider.class).getCertificate(alias);
    }

    @Path("{alias}")
    @PUT
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Upsert certificate Returns a trusted certificate.")
    public CertificateRepresentation upsertCertificate(String alias, CertificateRepresentation certificate) {
        auth.realm().requireManageRealm();

        CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
        try {
            provider.getCertificate(alias);
        } catch (NotFoundException e) {
            return provider.addCertificate(alias, certificate.certificate());
        }

        return provider.updateCertificate(alias, certificate.certificate());
    }

    @Path("{alias}")
    @PATCH
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Update certificate Updates a trusted certificate.")
    public void updateCertificate(String alias, CertificateRepresentation certificate) throws CertificateException {
        auth.realm().requireManageRealm();

        session.getProvider(CertificateTruststoreProvider.class).updateCertificate(alias, certificate.certificate());
    }

    @Path("{alias}")
    @DELETE
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Remove certificate Removes a trusted certificate.")
    public void removeCertificate(String alias) {
        auth.realm().requireManageRealm();

        session.getProvider(CertificateTruststoreProvider.class).removeCertificate(alias);
    }

}
