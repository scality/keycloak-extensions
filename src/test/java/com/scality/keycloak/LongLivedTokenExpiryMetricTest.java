package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;

public class LongLivedTokenExpiryMetricTest {

    private static final String REALM = "long-lived-metric";
    private static final String ALLOW_ATTRIBUTE = "scality.sa.longLivedTokens";
    private static final String METRIC = "keycloak_long_lived_token_expiry_timestamp_seconds";
    private static final int MANAGEMENT_PORT = 9000;
    private static final Duration REFRESH_INTERVAL = Duration.ofSeconds(15);

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
                .withEnabledMetrics()
                .withEnv("KC_SPI_ADMIN_REALM_RESTAPI_EXTENSION__LONG_LIVED_TOKENS__METRIC_REFRESH_INTERVAL",
                        REFRESH_INTERVAL.getSeconds() + "s");
        keycloak.addExposedPort(MANAGEMENT_PORT);
        keycloak.start();

        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(REALM);
        realmRepresentation.setEnabled(true);
        keycloak.getKeycloakAdminClient().realms().create(realmRepresentation);
        realm = keycloak.getKeycloakAdminClient().realm(REALM);
    }

    @AfterAll
    static void stopKeycloak() {
        keycloak.stop();
    }

    @Test
    public void an_issued_token_is_exported_with_its_expiry_until_it_is_revoked() throws Exception {
        String clientUuid = createClient("grafana");

        JsonNode issued = issue(clientUuid, "{\"lifespan\": 3600, \"label\": \"secret-looking label\"}");
        String jti = issued.get("jti").asText();

        String series = seriesOf(jti, scrape()).orElseThrow(() -> new AssertionError("no series for " + jti));
        assertTrue(series.contains("realm=\"" + REALM + "\""), series);
        assertTrue(series.contains("client_id=\"grafana\""), series);
        assertFalse(series.contains("secret-looking"), series);
        assertEquals(issued.get("exp").asLong(), expiryOf(series));

        assertEquals(204, revoke(jti).statusCode());
        assertTrue(seriesOf(jti, scrape()).isEmpty(), "a revoked token is still exported");
    }

    @Test
    public void an_expired_token_is_no_longer_exported() throws Exception {
        String clientUuid = createClient("centreon");
        String jti = issue(clientUuid, "{\"lifespan\": 2}").get("jti").asText();
        assertTrue(seriesOf(jti, scrape()).isPresent(), "the token is not exported once issued");

        long deadline = System.nanoTime() + REFRESH_INTERVAL.multipliedBy(2).toNanos();
        while (seriesOf(jti, scrape()).isPresent()) {
            assertTrue(System.nanoTime() < deadline, "an expired token is still exported");
            Thread.sleep(1000);
        }
    }

    private static String createClient(String clientId) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setEnabled(true);
        client.setPublicClient(false);
        client.setServiceAccountsEnabled(true);
        client.setStandardFlowEnabled(false);
        client.setAttributes(Map.of(ALLOW_ATTRIBUTE, "true"));
        try (Response response = realm.clients().create(client)) {
            assertEquals(201, response.getStatus());
            String location = response.getLocation().getPath();
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    private static Optional<String> seriesOf(String jti, String metrics) {
        return metrics.lines()
                .filter(line -> line.startsWith(METRIC + "{") && line.contains("jti=\"" + jti + "\""))
                .findFirst();
    }

    // Prometheus writes a gauge as a float, in exponent form for an epoch timestamp.
    private static long expiryOf(String series) {
        Matcher matcher = Pattern.compile("}\\s+(\\S+)").matcher(series);
        assertTrue(matcher.find(), series);
        return (long) Double.parseDouble(matcher.group(1));
    }

    private static String scrape() throws Exception {
        URI uri = URI.create("http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(MANAGEMENT_PORT)
                + "/metrics");
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(uri).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        return response.body();
    }

    private static JsonNode issue(String clientUuid, String body) throws Exception {
        HttpResponse<String> response = http.send(adminRequest("clients/" + clientUuid)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return objectMapper.readTree(response.body());
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
