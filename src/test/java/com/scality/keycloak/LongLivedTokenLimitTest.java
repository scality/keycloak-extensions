package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    private static RealmResource realm;

    @BeforeAll
    static void startKeycloak() {
        keycloak = FullImageName.createContainer()
                .withStartupTimeout(Duration.ofMinutes(5))
                .withProviderClassesFrom("target/classes")
                .withEnv("KC_SPI_ADMIN_REALM_RESTAPI_EXTENSION__LONG_LIVED_TOKENS__MAX_ACTIVE_TOKENS", "3")
                .withEnv("KC_SPI_ADMIN_REALM_RESTAPI_EXTENSION__LONG_LIVED_TOKENS__MAX_ACTIVE_TOKENS_PER_CLIENT", "2");
        keycloak.start();

        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(REALM);
        realmRepresentation.setEnabled(true);
        keycloak.getKeycloakAdminClient().realms().create(realmRepresentation);
        realm = keycloak.getKeycloakAdminClient().realm(REALM);
    }

    private static String createClient(String clientId) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setEnabled(true);
        client.setPublicClient(false);
        client.setServiceAccountsEnabled(true);
        client.setStandardFlowEnabled(false);
        try (Response response = realm.clients().create(client)) {
            assertEquals(201, response.getStatus());
            String location = response.getLocation().getPath();
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    @AfterAll
    static void stopKeycloak() {
        keycloak.stop();
    }

    @Test
    public void only_active_tokens_count_towards_the_client_and_realm_limits() throws Exception {
        String monitoring = createClient("monitoring");
        String backup = createClient("backup");
        String reporting = createClient("reporting");

        String revoked = assertIssued(issue(monitoring, "{\"lifespan\": 3600}"));
        assertIssued(issue(monitoring, "{\"lifespan\": 10}"));
        assertRefused(issue(monitoring, "{\"lifespan\": 3600}"), "Client monitoring");
        assertIssued(issue(backup, "{\"lifespan\": 3600}"));
        assertRefused(issue(reporting, "{\"lifespan\": 3600}"), "The realm");

        Thread.sleep(11000);
        assertIssued(issue(monitoring, "{\"lifespan\": 3600}"));
        assertRefused(issue(monitoring, "{\"lifespan\": 3600}"), "Client monitoring");

        assertEquals(204, revoke(revoked).statusCode());
        assertIssued(issue(reporting, "{\"lifespan\": 3600}"));
    }

    private static void assertRefused(HttpResponse<String> response, String limitHolder) {
        assertEquals(409, response.statusCode(), response.body());
        assertTrue(response.body().contains(limitHolder), response.body());
    }

    private static String assertIssued(HttpResponse<String> response) throws Exception {
        assertEquals(200, response.statusCode(), response.body());
        return objectMapper.readTree(response.body()).get("jti").asText();
    }

    private static HttpResponse<String> issue(String clientUuid, String body) throws Exception {
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
