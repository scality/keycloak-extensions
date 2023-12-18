package com.scality.keycloak.hostname;

import java.net.URI;

import org.keycloak.models.KeycloakSession;
import org.keycloak.url.DefaultHostnameProvider;

public class ScalityHostnameProvider extends DefaultHostnameProvider {

    public ScalityHostnameProvider(KeycloakSession session, URI frontendUri, URI adminUri,
            boolean forceBackendUrlToFrontendUrl) {
        super(session, frontendUri, adminUri, forceBackendUrlToFrontendUrl);
    }

}
