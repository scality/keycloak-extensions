package com.scality.keycloak;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.AccessTokenResponse;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.NotAuthorizedException;

public class TokenProvider {
    private int getTokenFailedAttemps = 0;

    public String getToken(KeycloakContainer keycloak) {
        try {
            Keycloak keycloakClient = keycloak.getKeycloakAdminClient();
            AccessTokenResponse accessTokenResponse = keycloakClient.tokenManager().getAccessToken();
            return accessTokenResponse.getToken();
        } catch (NotAuthorizedException e) {
            if (this.getTokenFailedAttemps > 3) {
                throw e;
            }
            this.getTokenFailedAttemps++;
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e1) {
                // ignore
            }
            return getToken(keycloak);
        }

    }
}
