package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;

// Liquibase runs a changeset once, so the test deletes its changelog row and restarts Keycloak to replay it.
public class LongLivedTokenAllowMigrationTest {

    private static final String REALM = "long-lived-migration";
    private static final String ALLOW_ATTRIBUTE = "scality.sa.longLivedTokens";
    private static final String CHANGESET_ID = "long-lived-token-1.2";

    private static final HttpClient http = HttpClient.newHttpClient();
    private static final TokenProvider tokenProvider = new TokenProvider();

    private static Network network;
    private static GenericContainer<?> postgres;
    private static KeycloakContainer keycloak;

    @BeforeAll
    static void createContainers() {
        network = Network.newNetwork();
        postgres = new GenericContainer<>("postgres:16-alpine")
                .withNetwork(network)
                .withNetworkAliases("postgres")
                .withEnv("POSTGRES_DB", "keycloak")
                .withEnv("POSTGRES_USER", "keycloak")
                .withEnv("POSTGRES_PASSWORD", "keycloak")
                .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));
        postgres.start();
        keycloak = FullImageName.createContainer()
                .withStartupTimeout(Duration.ofMinutes(5))
                .withProviderClassesFrom("target/classes")
                .withNetwork(network)
                .withEnv("KC_DB", "postgres")
                .withEnv("KC_DB_URL", "jdbc:postgresql://postgres:5432/keycloak")
                .withEnv("KC_DB_USERNAME", "keycloak")
                .withEnv("KC_DB_PASSWORD", "keycloak");
    }

    @AfterAll
    static void stopContainers() {
        keycloak.stop();
        postgres.stop();
        network.close();
    }

    @Test
    public void upgrade_allows_the_clients_that_already_have_tokens_and_keeps_an_explicit_choice() throws Exception {
        keycloak.start();
        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(REALM);
        realmRepresentation.setEnabled(true);
        keycloak.getKeycloakAdminClient().realms().create(realmRepresentation);

        String legacy = createClient("legacy");
        String optedOut = createClient("opted-out");
        String untouched = createClient("untouched");
        assertEquals(200, issue(legacy).statusCode());
        assertEquals(200, issue(optedOut).statusCode());
        keycloak.stop();

        sql("DELETE FROM CLIENT_ATTRIBUTES WHERE NAME = '" + ALLOW_ATTRIBUTE + "' AND CLIENT_ID IN ('"
                + legacy + "', '" + untouched + "')");
        sql("UPDATE CLIENT_ATTRIBUTES SET VALUE = 'false' WHERE NAME = '" + ALLOW_ATTRIBUTE
                + "' AND CLIENT_ID = '" + optedOut + "'");
        sql("DELETE FROM DATABASECHANGELOG_LONG_LIVED WHERE ID = '" + CHANGESET_ID + "'");

        keycloak.start();
        assertEquals("true", allowAttribute(legacy));
        assertEquals("false", allowAttribute(optedOut));
        assertEquals("", allowAttribute(untouched));
        assertEquals(200, issue(legacy).statusCode());
        assertEquals(400, issue(untouched).statusCode());
    }

    private static String createClient(String clientId) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setEnabled(true);
        client.setPublicClient(false);
        client.setServiceAccountsEnabled(true);
        client.setStandardFlowEnabled(false);
        client.setAttributes(Map.of(ALLOW_ATTRIBUTE, "true"));
        try (Response response = keycloak.getKeycloakAdminClient().realm(REALM).clients().create(client)) {
            assertEquals(201, response.getStatus());
            String location = response.getLocation().getPath();
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    private static HttpResponse<String> issue(String clientUuid) throws Exception {
        return http.send(HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/admin/realms/" + REALM
                        + "/long-lived-tokens/clients/" + clientUuid))
                .header("Authorization", "Bearer " + tokenProvider.getToken(keycloak))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"lifespan\": 3600}"))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String allowAttribute(String clientUuid) throws Exception {
        return sql("SELECT VALUE FROM CLIENT_ATTRIBUTES WHERE NAME = '" + ALLOW_ATTRIBUTE
                + "' AND CLIENT_ID = '" + clientUuid + "'").trim();
    }

    private static String sql(String statement) throws Exception {
        Container.ExecResult result = postgres.execInContainer("psql", "-U", "keycloak", "-d", "keycloak",
                "-tAc", statement);
        assertEquals(0, result.getExitCode(), result.getStderr());
        return result.getStdout();
    }
}
