package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
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
    private static final long TWO_DAYS = 2L * 24 * 60 * 60;
    private static final String KEY_PROVIDER_TYPE = "org.keycloak.keys.KeyProvider";

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
        // The tests read and build keys themselves. Set explicitly: the test classpath also holds the
        // FIPS provider, which detection could pick and which cannot run here.
        CryptoIntegration.setProvider(new DefaultCryptoProvider());
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
    public void token_is_signed_with_its_own_published_key() throws Exception {
        String token = issueToken(serviceAccountClientUuid, "{\"lifespan\": 3600}");
        String jti = verify(token).getId();

        assertEquals(jti, TokenVerifier.create(token, AccessToken.class).getHeader().getKeyId());
        assertTrue(certKeyIds().contains(jti));
        assertEquals("RS256|t", queryRegistry("SELECT ALGORITHM, PUBLIC_KEY IS NOT NULL FROM LONG_LIVED_TOKEN WHERE JTI = '"
                + jti + "'").trim());
    }

    @Test
    public void token_outlives_a_rotation_of_the_realm_keys() throws Exception {
        String token = issueToken(serviceAccountClientUuid, "{\"lifespan\": 3600}");
        String realmId = realm.toRepresentation().getId();
        List<ComponentRepresentation> realmKeys = realm.components().query(realmId, KEY_PROVIDER_TYPE).stream()
                .filter(component -> "rsa-generated".equals(component.getProviderId()))
                .toList();

        ComponentRepresentation rotated = new ComponentRepresentation();
        rotated.setName("rotated");
        rotated.setProviderId("rsa-generated");
        rotated.setProviderType(KEY_PROVIDER_TYPE);
        rotated.setParentId(realmId);
        rotated.setConfig(new MultivaluedHashMap<>(Map.of("priority", List.of("200"))));
        realm.components().add(rotated).close();
        for (ComponentRepresentation key : realmKeys) {
            key.getConfig().putSingle("enabled", "false");
            realm.components().component(key.getId()).update(key);
        }

        verify(token);
    }

    @Test
    public void disabling_the_key_provider_unpublishes_every_token_key() throws Exception {
        String jti = verify(issueToken(serviceAccountClientUuid, "{\"lifespan\": 3600}")).getId();
        ComponentRepresentation provider = realm.components()
                .query(realm.toRepresentation().getId(), KEY_PROVIDER_TYPE).stream()
                .filter(component -> "long-lived-tokens".equals(component.getProviderId()))
                .findFirst().orElseThrow();

        provider.getConfig().putSingle("enabled", "false");
        realm.components().component(provider.getId()).update(provider);
        assertFalse(certKeyIds().contains(jti));

        provider.getConfig().putSingle("enabled", "true");
        realm.components().component(provider.getId()).update(provider);
        assertTrue(certKeyIds().contains(jti));
    }

    @Test
    public void client_signing_with_an_elliptic_curve_gets_a_token_signed_the_same_way() throws Exception {
        String clientUuid = createClient("ec-app", false, true);
        setAccessTokenAlgorithm(clientUuid, "ES256");

        String token = issueToken(clientUuid, "{\"lifespan\": 3600}");

        assertEquals("ES256", TokenVerifier.create(token, AccessToken.class).getHeader().getRawAlgorithm());
        verify(token);
    }

    @Test
    public void client_signing_with_a_shared_secret_is_rejected() throws Exception {
        String clientUuid = createClient("hmac-app", false, true);
        setAccessTokenAlgorithm(clientUuid, "HS256");

        assertEquals(400, issue(clientUuid, "{}", adminToken()).statusCode());
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
    public void failing_to_record_the_admin_event_cancels_the_issuing() throws Exception {
        RealmRepresentation realmWithAdminEvents = realm.toRepresentation();
        realmWithAdminEvents.setAdminEventsEnabled(true);
        realm.update(realmWithAdminEvents);
        queryRegistry("CREATE FUNCTION fail_admin_event() RETURNS trigger LANGUAGE plpgsql AS "
                + "$$ BEGIN RAISE EXCEPTION 'admin event store unavailable'; END $$; "
                + "CREATE TRIGGER fail_admin_event BEFORE INSERT ON ADMIN_EVENT_ENTITY "
                + "FOR EACH ROW EXECUTE FUNCTION fail_admin_event();");
        try {
            long issuedLogLines = issuedLogLines();
            HttpResponse<String> response = issue(serviceAccountClientUuid, "{\"label\": \"unaudited\"}", adminToken());

            assertEquals(500, response.statusCode(), response.body());
            assertFalse(response.body().contains("\"token\""), response.body());
            assertEquals("0",
                    queryRegistry("SELECT COUNT(*) FROM LONG_LIVED_TOKEN WHERE LABEL = 'unaudited'").trim());
            assertEquals(issuedLogLines, issuedLogLines());
        } finally {
            queryRegistry("DROP TRIGGER fail_admin_event ON ADMIN_EVENT_ENTITY; DROP FUNCTION fail_admin_event();");
            realmWithAdminEvents.setAdminEventsEnabled(false);
            realm.update(realmWithAdminEvents);
        }
    }

    @Test
    public void lifespan_defaults_to_one_year() throws Exception {
        HttpResponse<String> response = issue(serviceAccountClientUuid, "{}", adminToken());

        assertEquals(200, response.statusCode(), response.body());
        AccessToken token = verify(objectMapper.readTree(response.body()).get("token").asText());
        assertEquals(ONE_YEAR, token.getExp() - token.getIat());
    }

    @Test
    public void lifespan_accepts_a_duration_with_a_unit() throws Exception {
        for (String lifespan : new String[] { "2d", "48h", "PT48H" }) {
            HttpResponse<String> response = issue(serviceAccountClientUuid,
                    "{\"lifespan\": \"" + lifespan + "\"}", adminToken());

            assertEquals(200, response.statusCode(), lifespan + ": " + response.body());
            AccessToken token = verify(objectMapper.readTree(response.body()).get("token").asText());
            assertEquals(TWO_DAYS, token.getExp() - token.getIat(), lifespan);
        }
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
    public void lifespan_outside_bounds_or_malformed_is_rejected() throws Exception {
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": " + (ONE_YEAR + 1) + "}", adminToken())
                .statusCode());
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": 0}", adminToken()).statusCode());
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": \"366d\"}", adminToken()).statusCode());
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": \"500ms\"}", adminToken()).statusCode());
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": \"1500ms\"}", adminToken()).statusCode());
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": \"two days\"}", adminToken()).statusCode());
        assertEquals(400, issue(serviceAccountClientUuid, "{\"lifespan\": \"\"}", adminToken()).statusCode());
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

    private static void setAccessTokenAlgorithm(String clientUuid, String algorithm) {
        ClientRepresentation client = realm.clients().get(clientUuid).toRepresentation();
        client.getAttributes().put("access.token.signed.response.alg", algorithm);
        realm.clients().get(clientUuid).update(client);
    }

    private static List<String> certKeyIds() throws IOException, InterruptedException {
        HttpResponse<String> certs = http.send(
                HttpRequest.newBuilder().uri(URI.create(realmUrl() + "/protocol/openid-connect/certs")).build(),
                HttpResponse.BodyHandlers.ofString());
        return List.of(objectMapper.readValue(certs.body(), JSONWebKeySet.class).getKeys()).stream()
                .map(JWK::getKeyId)
                .toList();
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

    private static String issueToken(String clientUuid, String body) throws Exception {
        HttpResponse<String> response = issue(clientUuid, body, adminToken());
        assertEquals(200, response.statusCode(), response.body());
        return objectMapper.readTree(response.body()).get("token").asText();
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

    private static long issuedLogLines() {
        return keycloak.getLogs().lines().filter(line -> line.contains("Long-lived token ")
                && line.contains(" issued for client ")).count();
    }

    private static String queryRegistry(String sql) throws IOException, InterruptedException {
        Container.ExecResult result = postgres.execInContainer("psql", "-U", "keycloak", "-d", "keycloak",
                "-tAc", sql);
        assertEquals(0, result.getExitCode(), result.getStderr());
        return result.getStdout();
    }
}
