package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;

public class LongLivedTokenLimitTest {

    private static final String REALM = "long-lived-limit";

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final HttpClient http = HttpClient.newHttpClient();
    private static final TokenProvider tokenProvider = new TokenProvider();

    private static KeycloakContainer keycloak;
    private static String clientUuid;

    @BeforeAll
    static void startKeycloak() {
        keycloak = FullImageName.createContainer()
                .withStartupTimeout(Duration.ofMinutes(5))
                .withProviderClassesFrom("target/classes")
                .withEnv("KC_SPI_ADMIN_REALM_RESTAPI_EXTENSION__LONG_LIVED_TOKENS__MAX_ACTIVE_TOKENS", "2");
        keycloak.start();

        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(REALM);
        realmRepresentation.setEnabled(true);
        keycloak.getKeycloakAdminClient().realms().create(realmRepresentation);
        RealmResource realm = keycloak.getKeycloakAdminClient().realm(REALM);

        ClientRepresentation client = new ClientRepresentation();
        client.setClientId("monitoring");
        client.setEnabled(true);
        client.setPublicClient(false);
        client.setServiceAccountsEnabled(true);
        client.setStandardFlowEnabled(false);
        try (Response response = realm.clients().create(client)) {
            assertEquals(201, response.getStatus());
            String location = response.getLocation().getPath();
            clientUuid = location.substring(location.lastIndexOf('/') + 1);
        }
    }

    @AfterAll
    static void stopKeycloak() {
        keycloak.stop();
    }

    @Test
    public void only_active_tokens_count_towards_the_realm_limit() throws Exception {
        String revoked = assertIssued(issue("{\"lifespan\": 3600}"));
        assertIssued(issue("{\"lifespan\": 3}"));
        assertEquals(409, issue("{\"lifespan\": 3600}").statusCode());

        Thread.sleep(4000);
        assertIssued(issue("{\"lifespan\": 3600}"));
        assertEquals(409, issue("{\"lifespan\": 3600}").statusCode());

        assertEquals(204, revoke(revoked).statusCode());
        assertIssued(issue("{\"lifespan\": 3600}"));
    }

    private static String assertIssued(HttpResponse<String> response) throws Exception {
        assertEquals(200, response.statusCode(), response.body());
        return objectMapper.readTree(response.body()).get("jti").asText();
    }

    private static HttpResponse<String> issue(String body) throws Exception {
        return http.send(adminRequest("clients/" + clientUuid)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> revoke(String jti) throws Exception {
        return http.send(adminRequest(jti + "/revoke").POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpRequest.Builder adminRequest(String path) {
        return HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/admin/realms/" + REALM + "/long-lived-tokens/" + path))
                .header("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
    }
}
