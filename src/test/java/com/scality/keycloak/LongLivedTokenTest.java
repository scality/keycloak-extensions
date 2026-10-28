package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;

public class LongLivedTokenTest {

    private static final String REALM = "long-lived";
    private static final String READER_ROLE = "metrics-reader";
    private static final long TEN_HOURS = 10 * 60 * 60;
    private static final long ONE_YEAR = 365L * 24 * 60 * 60;

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final HttpClient http = HttpClient.newHttpClient();
    private static final TokenProvider tokenProvider = new TokenProvider();

    private static Network network;
    private static GenericContainer<?> postgres;
    private static KeycloakContainer keycloak;
    private static RealmResource realm;
    private static String serviceAccountClientUuid;
    private static String adminUserId;

    // PostgreSQL rather than the default H2, so the test can read the registry with psql while
    // Keycloak holds the database open.
    @BeforeAll
    static void startKeycloak() {
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
        keycloak.start();

        Keycloak admin = keycloak.getKeycloakAdminClient();
        adminUserId = admin.realm("master").users().search(keycloak.getAdminUsername(), true).get(0).getId();

        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(REALM);
        realmRepresentation.setEnabled(true);
        admin.realms().create(realmRepresentation);
        realm = admin.realm(REALM);

        RoleRepresentation readerRole = new RoleRepresentation();
        readerRole.setName(READER_ROLE);
        realm.roles().create(readerRole);
        RoleRepresentation unassignedRole = new RoleRepresentation();
        unassignedRole.setName("unassigned");
        realm.roles().create(unassignedRole);

        serviceAccountClientUuid = createClient("monitoring", false, true);
        String serviceAccountId = realm.clients().get(serviceAccountClientUuid).getServiceAccountUser().getId();
        realm.users().get(serviceAccountId).roles().realmLevel()
                .add(List.of(realm.roles().get(READER_ROLE).toRepresentation()));
    }

    @AfterAll
    static void stopKeycloak() {
        keycloak.stop();
        postgres.stop();
        network.close();
    }

    @Test
    public void issued_token_outlives_the_session_limit_and_is_recorded() throws Exception {
        long lifespan = 2 * 24 * 60 * 60;
        HttpResponse<String> response = issue(serviceAccountClientUuid,
                "{\"lifespan\": " + lifespan + ", \"label\": \"dashboard\"}", adminToken());

        assertEquals(200, response.statusCode(), response.body());
        JsonNode body = objectMapper.readTree(response.body());
        AccessToken token = verify(body.get("token").asText());

        assertEquals(body.get("jti").asText(), token.getId());
        assertEquals(body.get("exp").asLong(), token.getExp());
        assertEquals(lifespan, token.getExp() - token.getIat());
        assertTrue(token.getExp() - token.getIat() > TEN_HOURS);
        assertEquals(Boolean.TRUE, token.getOtherClaims().get("long_lived"));

        String row = queryRegistry("SELECT CLIENT_ID, LABEL, EXP, REVOKED, CREATED_BY FROM LONG_LIVED_TOKEN WHERE JTI = '"
                + token.getId() + "'");
        assertTrue(row.contains(serviceAccountClientUuid), row);
        assertTrue(row.contains("dashboard"), row);
        assertTrue(row.contains(String.valueOf(token.getExp())), row);
        assertTrue(row.contains(adminUserId), row);
    }

    @Test
    public void deleting_the_client_removes_its_tokens_from_the_registry() throws Exception {
        String clientUuid = createClient("short-lived-app", false, true);
        HttpResponse<String> response = issue(clientUuid, "{\"lifespan\": 60}", adminToken());
        assertEquals(200, response.statusCode(), response.body());
        String jti = objectMapper.readTree(response.body()).get("jti").asText();
        String count = "SELECT COUNT(*) FROM LONG_LIVED_TOKEN WHERE JTI = '" + jti + "'";
        assertEquals("1", queryRegistry(count).trim());

        realm.clients().get(clientUuid).remove();

        assertEquals("0", queryRegistry(count).trim());
    }

    @Test
    public void lifespan_defaults_to_one_year() throws Exception {
        HttpResponse<String> response = issue(serviceAccountClientUuid, "{}", adminToken());

        assertEquals(200, response.statusCode(), response.body());
        AccessToken token = verify(objectMapper.readTree(response.body()).get("token").asText());
        assertEquals(ONE_YEAR, token.getExp() - token.getIat());
    }

    @Test
    public void token_carries_the_same_roles_as_a_client_credentials_token() throws Exception {
        HttpResponse<String> response = issue(serviceAccountClientUuid, "{\"lifespan\": 3600}", adminToken());
        assertEquals(200, response.statusCode(), response.body());
        AccessToken longLived = verify(objectMapper.readTree(response.body()).get("token").asText());

        AccessToken regular = verify(clientCredentialsToken("monitoring"));

        assertTrue(longLived.getRealmAccess().getRoles().contains(READER_ROLE));
        assertTrue(!longLived.getRealmAccess().getRoles().contains("unassigned"));
        assertEquals(regular.getRealmAccess().getRoles(), longLived.getRealmAccess().getRoles());
        assertEquals(regular.getResourceAccess().keySet(), longLived.getResourceAccess().keySet());
        regular.getResourceAccess().forEach((clientId, access) -> assertEquals(access.getRoles(),
                longLived.getResourceAccess(clientId).getRoles(), clientId));
        assertEquals(regular.getSubject(), longLived.getSubject());
        assertEquals(regular.getIssuedFor(), longLived.getIssuedFor());
    }

    @Test
    public void caller_without_manage_clients_is_forbidden() throws Exception {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("viewer");
        user.setEnabled(true);
        user.setFirstName("View");
        user.setLastName("Only");
        user.setEmail("viewer@example.com");
        user.setEmailVerified(true);
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue("viewer");
        password.setTemporary(false);
        user.setCredentials(List.of(password));
        String userId = createdId(realm.users().create(user));

        String realmManagement = realm.clients().findByClientId("realm-management").get(0).getId();
        realm.users().get(userId).roles().clientLevel(realmManagement)
                .add(List.of(realm.clients().get(realmManagement).roles().get("view-clients").toRepresentation()));

        HttpResponse<String> response = issue(serviceAccountClientUuid, "{}", passwordToken("viewer", "viewer"));

        assertEquals(403, response.statusCode(), response.body());
    }

    @Test
    public void unknown_client_is_not_found() throws Exception {
        assertEquals(404, issue("00000000-0000-0000-0000-000000000000", "{}", adminToken()).statusCode());
    }

    @Test
    public void lifespan_outside_bounds_is_rejected() throws Exception {
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": " + (ONE_YEAR + 1) + "}", adminToken())
                .statusCode());
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": 0}", adminToken()).statusCode());
    }

    @Test
    public void public_client_is_rejected() throws Exception {
        String clientUuid = createClient("public-app", true, false);
        assertEquals(400, issue(clientUuid, "{}", adminToken()).statusCode());
    }

    @Test
    public void client_without_service_account_is_rejected() throws Exception {
        String clientUuid = createClient("web-app", false, false);
        assertEquals(400, issue(clientUuid, "{}", adminToken()).statusCode());
    }

    @Test
    public void client_with_certificate_bound_tokens_is_rejected() throws Exception {
        String clientUuid = createClient("bound-app", false, true);
        ClientRepresentation client = realm.clients().get(clientUuid).toRepresentation();
        client.getAttributes().put("tls.client.certificate.bound.access.tokens", "true");
        realm.clients().get(clientUuid).update(client);
        assertEquals(400, issue(clientUuid, "{}", adminToken()).statusCode());
    }

    @Test
    public void client_with_dpop_bound_tokens_is_rejected() throws Exception {
        String clientUuid = createClient("dpop-app", false, true);
        ClientRepresentation client = realm.clients().get(clientUuid).toRepresentation();
        client.getAttributes().put("dpop.bound.access.tokens", "true");
        realm.clients().get(clientUuid).update(client);
        assertEquals(400, issue(clientUuid, "{}", adminToken()).statusCode());
    }

    @Test
    public void disabled_client_is_rejected() throws Exception {
        String clientUuid = createClient("disabled-app", false, true);
        ClientRepresentation client = realm.clients().get(clientUuid).toRepresentation();
        client.setEnabled(false);
        realm.clients().get(clientUuid).update(client);
        assertEquals(400, issue(clientUuid, "{}", adminToken()).statusCode());
    }

    private static String createClient(String clientId, boolean publicClient, boolean serviceAccount) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setEnabled(true);
        client.setPublicClient(publicClient);
        client.setServiceAccountsEnabled(serviceAccount);
        client.setStandardFlowEnabled(!serviceAccount);
        client.setSecret(clientId + "-secret");
        return createdId(realm.clients().create(client));
    }

    private static String createdId(Response response) {
        try (response) {
            assertEquals(201, response.getStatus());
            String location = response.getLocation().getPath();
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    private static String adminToken() {
        return tokenProvider.getToken(keycloak);
    }

    private static HttpResponse<String> issue(String clientUuid, String body, String bearer)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/admin/realms/" + REALM
                        + "/long-lived-tokens/clients/" + clientUuid))
                .header("Authorization", "Bearer " + bearer)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String clientCredentialsToken(String clientId) throws IOException, InterruptedException {
        return tokenEndpoint(Map.of("grant_type", "client_credentials", "client_id", clientId,
                "client_secret", clientId + "-secret"));
    }

    private static String passwordToken(String username, String password) throws IOException, InterruptedException {
        return tokenEndpoint(Map.of("grant_type", "password", "client_id", "admin-cli",
                "username", username, "password", password));
    }

    private static String tokenEndpoint(Map<String, String> form) throws IOException, InterruptedException {
        StringBuilder body = new StringBuilder();
        form.forEach((key, value) -> body.append(body.length() == 0 ? "" : "&")
                .append(key).append('=').append(URLEncoder.encode(value, StandardCharsets.UTF_8)));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(realmUrl() + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return objectMapper.readTree(response.body()).get("access_token").asText();
    }

    private static String realmUrl() {
        return keycloak.getAuthServerUrl() + "/realms/" + REALM;
    }

    private static AccessToken verify(String token) throws Exception {
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class)
                .withChecks(TokenVerifier.IS_ACTIVE, new TokenVerifier.RealmUrlCheck(realmUrl()));
        String kid = verifier.getHeader().getKeyId();

        HttpResponse<String> certs = http.send(
                HttpRequest.newBuilder().uri(URI.create(realmUrl() + "/protocol/openid-connect/certs")).build(),
                HttpResponse.BodyHandlers.ofString());
        JSONWebKeySet keys = objectMapper.readValue(certs.body(), JSONWebKeySet.class);
        for (JWK key : keys.getKeys()) {
            if (kid.equals(key.getKeyId()) && KeyUse.SIG.getSpecName().equals(key.getPublicKeyUse())) {
                PublicKey publicKey = JWKParser.create(key).toPublicKey();
                return verifier.publicKey(publicKey).verify().getToken();
            }
        }
        throw new AssertionError("No realm key matches the token key id " + kid);
    }

    private static String queryRegistry(String sql) throws IOException, InterruptedException {
        Container.ExecResult result = postgres.execInContainer("psql", "-U", "keycloak", "-d", "keycloak",
                "-tAc", sql);
        assertEquals(0, result.getExitCode(), result.getStderr());
        return result.getStdout();
    }
}
