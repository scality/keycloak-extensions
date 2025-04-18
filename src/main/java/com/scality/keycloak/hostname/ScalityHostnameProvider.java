package com.scality.keycloak.hostname;

import java.net.URI;

import org.keycloak.models.KeycloakSession;
import org.keycloak.url.HostnameV2Provider;

public class ScalityHostnameProvider extends HostnameV2Provider {

    public ScalityHostnameProvider(KeycloakSession session, String hostname, URI frontendUri, URI adminUri,
            boolean forceBackendUrlToFrontendUrl) {
        super(session, hostname, frontendUri, adminUri, forceBackendUrlToFrontendUrl);
    }

}
