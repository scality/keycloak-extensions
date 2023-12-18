package com.scality.keycloak.hostname;

import java.net.URI;
import java.net.URISyntaxException;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.url.DefaultHostnameProviderFactory;
import org.keycloak.urls.HostnameProvider;

public class ScalityHostnameProviderFactory extends DefaultHostnameProviderFactory {

    private static final Logger LOGGER = Logger.getLogger(ScalityHostnameProviderFactory.class);

    private URI frontendUri;
    private URI adminUri;
    private boolean forceBackendUrlToFrontendUrl;

    @Override
    public HostnameProvider create(KeycloakSession session) {
        return new ScalityHostnameProvider(session, frontendUri, adminUri, forceBackendUrlToFrontendUrl);
    }

    @Override
    public void init(Config.Scope config) {
        String frontendUrl = config.get("frontendUrl");
        String adminUrl = config.get("adminUrl");

        if (frontendUrl != null && !frontendUrl.isEmpty()) {
            try {
                frontendUri = new URI(frontendUrl);
            } catch (URISyntaxException e) {
                throw new RuntimeException("Invalid value for frontendUrl", e);
            }
        }

        if (adminUrl != null && !adminUrl.isEmpty()) {
            try {
                adminUri = new URI(adminUrl);
            } catch (URISyntaxException e) {
                throw new RuntimeException("Invalid value for adminUrl", e);
            }
        }

        forceBackendUrlToFrontendUrl = config.getBoolean("forceBackendUrlToFrontendUrl", false);

        LOGGER.infov("Frontend: {0}, Admin: {1}, Backend: {2}",
                frontendUri != null ? frontendUri.toString() : "<request>",
                adminUri != null ? adminUri.toString() : "<frontend>",
                forceBackendUrlToFrontendUrl ? "<frontend>" : "<request>");
    }

    @Override
    public String getId() {
        return "default";
    }

    @Override
    public int order() {
        return 1;
    }
}
