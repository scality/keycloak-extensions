package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.MountableFile;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;

/**
 * Behavioural test for RING-54200 (authenticator approach): when LDAP is unreachable, the browser
 * login shows a dedicated "service temporarily unavailable" message (not "Invalid username or
 * password", not a 500), and imported users are not purged.
 */
public class LdapOutageAuthenticatorTest {
    private final Logger logger = LoggerFactory.getLogger(LdapOutageAuthenticatorTest.class);
    private final TokenProvider tokenProvider = new TokenProvider();
    private final ObjectMapper mapper = new ObjectMapper();
    private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+login-actions/authenticate[^\"]*)\"");

    private String admin(KeycloakContainer kc) {
        return tokenProvider.getToken(kc);
    }

    private String post(KeycloakContainer kc, String path, String json) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(kc.getAuthServerUrl() + path).openConnection();
        c.setRequestMethod("POST");
        c.setRequestProperty("Authorization", "Bearer " + admin(kc));
        c.setRequestProperty("Content-Type", "application/json");
        c.setDoOutput(true);
        c.getOutputStream().write(json.getBytes(StandardCharsets.UTF_8));
        c.getOutputStream().close();
        int code = c.getResponseCode();
        assertTrue(code >= 200 && code < 300, "POST " + path + " -> " + code);
        return c.getHeaderField("Location");
    }

    private String get(KeycloakContainer kc, String path) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(kc.getAuthServerUrl() + path).openConnection();
        c.setRequestProperty("Authorization", "Bearer " + admin(kc));
        return IOUtils.toString(c.getInputStream(), StandardCharsets.UTF_8);
    }

    private String masterRealmId(KeycloakContainer kc) throws IOException {
        Map<String, Object> realm = mapper.readValue(get(kc, "/admin/realms/master"),
                new TypeReference<Map<String, Object>>() {
                });
        return (String) realm.get("id");
    }

    private String createFederation(KeycloakContainer kc) throws IOException {
        String parent = masterRealmId(kc);
        String body = "{\"name\":\"ldap\",\"providerId\":\"ldap-without-mappers\","
                + "\"providerType\":\"org.keycloak.storage.UserStorageProvider\",\"parentId\":\"" + parent + "\","
                + "\"config\":{\"enabled\":[\"true\"],\"vendor\":[\"other\"],\"connectionUrl\":[\"ldap://ldap.local\"],"
                + "\"bindDn\":[\"cn=admin,dc=ldap,dc=local\"],\"bindCredential\":[\"password\"],\"authType\":[\"simple\"],"
                + "\"usersDn\":[\"ou=people,dc=ldap,dc=local\"],\"usernameLDAPAttribute\":[\"uid\"],"
                + "\"rdnLDAPAttribute\":[\"uid\"],\"uuidLDAPAttribute\":[\"entryUUID\"],"
                + "\"userObjectClasses\":[\"inetOrgPerson\"],\"searchScope\":[\"1\"],\"editMode\":[\"UNSYNCED\"],"
                + "\"importEnabled\":[\"true\"],\"cachePolicy\":[\"NO_CACHE\"],"
                + "\"connectionTimeout\":[\"\"],\"readTimeout\":[\"\"],\"pagination\":[\"false\"]}}";
        String loc = post(kc, "/admin/realms/master/components", body);
        String fedId = loc.substring(loc.lastIndexOf('/') + 1);
        post(kc, "/admin/realms/master/components",
                "{\"name\":\"username\",\"providerId\":\"user-attribute-ldap-mapper\","
                        + "\"providerType\":\"org.keycloak.storage.ldap.mappers.LDAPStorageMapper\",\"parentId\":\"" + fedId + "\","
                        + "\"config\":{\"user.model.attribute\":[\"username\"],\"ldap.attribute\":[\"uid\"],"
                        + "\"read.only\":[\"true\"],\"always.read.value.from.ldap\":[\"false\"],\"is.mandatory.in.ldap\":[\"true\"]}}");
        return fedId;
    }

    /** A public standard-flow client without PKCE so we can drive the login form directly. */
    private void createBrowserClient(KeycloakContainer kc) throws IOException {
        post(kc, "/admin/realms/master/clients",
                "{\"clientId\":\"test-browser\",\"enabled\":true,\"publicClient\":true,\"standardFlowEnabled\":true,"
                        + "\"redirectUris\":[\"http://localhost/cb\"],\"webOrigins\":[\"*\"],\"attributes\":{\"pkce.code.challenge.method\":\"\"}}");
    }

    private void wireAuthenticator(KeycloakContainer kc) throws IOException {
        post(kc, "/admin/realms/master/authentication/flows/browser/copy", "{\"newName\":\"browser-ldap-aware\"}");
        List<Map<String, Object>> execs = mapper.readValue(
                get(kc, "/admin/realms/master/authentication/flows/browser-ldap-aware/executions"),
                new TypeReference<List<Map<String, Object>>>() {
                });
        String upfId = null;
        String formsAlias = null;
        for (Map<String, Object> e : execs) {
            if ("auth-username-password-form".equals(e.get("providerId"))) {
                upfId = (String) e.get("id");
            }
            String dn = String.valueOf(e.get("displayName"));
            if (dn.endsWith(" forms")) {
                formsAlias = dn;
            }
        }
        assertNotNull(upfId, "stock username-password-form execution");
        assertNotNull(formsAlias, "forms subflow");
        // delete stock execution
        HttpURLConnection del = (HttpURLConnection) new URL(
                kc.getAuthServerUrl() + "/admin/realms/master/authentication/executions/" + upfId).openConnection();
        del.setRequestMethod("DELETE");
        del.setRequestProperty("Authorization", "Bearer " + admin(kc));
        assertEquals(204, del.getResponseCode());
        // add ours to the forms subflow
        // Keycloak path segment needs %20, not the '+' that URLEncoder emits for spaces.
        String formsEnc = URLEncoder.encode(formsAlias, StandardCharsets.UTF_8).replace("+", "%20");
        post(kc, "/admin/realms/master/authentication/flows/" + formsEnc + "/executions/execution",
                "{\"provider\":\"ldap-aware-username-password\"}");
        // set REQUIRED + raise priority
        List<Map<String, Object>> execs2 = mapper.readValue(
                get(kc, "/admin/realms/master/authentication/flows/browser-ldap-aware/executions"),
                new TypeReference<List<Map<String, Object>>>() {
                });
        String newId = null;
        for (Map<String, Object> e : execs2) {
            if ("ldap-aware-username-password".equals(e.get("providerId"))) {
                newId = (String) e.get("id");
            }
        }
        assertNotNull(newId, "new authenticator execution");
        HttpURLConnection put = (HttpURLConnection) new URL(
                kc.getAuthServerUrl() + "/admin/realms/master/authentication/flows/browser-ldap-aware/executions")
                .openConnection();
        put.setRequestMethod("PUT");
        put.setRequestProperty("Authorization", "Bearer " + admin(kc));
        put.setRequestProperty("Content-Type", "application/json");
        put.setDoOutput(true);
        put.getOutputStream().write(("{\"id\":\"" + newId + "\",\"requirement\":\"REQUIRED\"}").getBytes());
        put.getOutputStream().close();
        assertEquals(204, put.getResponseCode());
        post(kc, "/admin/realms/master/authentication/executions/" + newId + "/raise-priority", "{}");
        // bind realm browserFlow
        Map<String, Object> realm = mapper.readValue(get(kc, "/admin/realms/master"),
                new TypeReference<Map<String, Object>>() {
                });
        realm.put("browserFlow", "browser-ldap-aware");
        // Allow the browser login flow over plain HTTP in the test (otherwise Keycloak marks session
        // cookies Secure and the credential POST fails with 400 "Cookie not found").
        realm.put("sslRequired", "NONE");
        HttpURLConnection bind = (HttpURLConnection) new URL(kc.getAuthServerUrl() + "/admin/realms/master")
                .openConnection();
        bind.setRequestMethod("PUT");
        bind.setRequestProperty("Authorization", "Bearer " + admin(kc));
        bind.setRequestProperty("Content-Type", "application/json");
        bind.setDoOutput(true);
        bind.getOutputStream().write(mapper.writeValueAsBytes(realm));
        bind.getOutputStream().close();
        assertEquals(204, bind.getResponseCode());
    }

    private record LoginResult(int status, String body) {
    }

    private static String snippet(String s) {
        if (s == null) {
            return "<null>";
        }
        String flat = s.replaceAll("<[^>]*>", " ").replaceAll("\\s+", " ").trim();
        return flat.length() > 300 ? flat.substring(0, 300) : flat;
    }

    /** Drive the browser auth-code login form; returns the final status + body of the credential POST. */
    private LoginResult login(KeycloakContainer kc, String user, String pass) throws Exception {
        HttpClient http = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        String authUrl = kc.getAuthServerUrl() + "/realms/master/protocol/openid-connect/auth"
                + "?client_id=test-browser&redirect_uri=" + URLEncoder.encode("http://localhost/cb", StandardCharsets.UTF_8)
                + "&response_type=code&scope=openid&state=st&nonce=no";
        HttpResponse<String> page = http.send(HttpRequest.newBuilder(URI.create(authUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        Matcher m = FORM_ACTION.matcher(page.body());
        assertTrue(m.find(), "login form action present");
        String action = m.group(1).replace("&amp;", "&");
        String form = "username=" + URLEncoder.encode(user, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(pass, StandardCharsets.UTF_8)
                + "&credentialId=";
        HttpResponse<String> resp = http.send(HttpRequest.newBuilder(URI.create(action))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        return new LoginResult(resp.statusCode(), resp.body());
    }

    private Map<String, Object> getUser(KeycloakContainer kc, String username) throws IOException {
        List<Map<String, Object>> users = mapper.readValue(
                get(kc, "/admin/realms/master/users?exact=true&username=" + username),
                new TypeReference<List<Map<String, Object>>>() {
                });
        return users.isEmpty() ? null : users.get(0);
    }

    @Test
    public void outage_login_shows_service_unavailable_and_keeps_imported_user() throws Exception {
        Network network = Network.newNetwork();
        try (GenericContainer<?> openldap = new GenericContainer<>("osixia/openldap:latest")
                .withCreateContainerCmdModifier(it -> it.withHostName("ldap.local"))
                .withNetwork(network)
                .withEnv("LDAP_DOMAIN", "ldap.local")
                .withEnv("LDAP_ADMIN_PASSWORD", "password")
                .withEnv("LDAP_TLS_VERIFY_CLIENT", "try")
                .withCopyFileToContainer(MountableFile.forClasspathResource("/outage-user.ldif"), "/outage-user.ldif")
                .withExposedPorts(389, 636)) {
            openldap.start();
            openldap.execInContainer("ldapmodify", "-x", "-D", "cn=admin,dc=ldap,dc=local", "-w", "password",
                    "-H", "ldap://ldap.local", "-f", "/outage-user.ldif");

            try (KeycloakContainer keycloak = FullImageName.createContainer()
                    .withNetwork(network)
                    .withStartupTimeout(Duration.ofMinutes(5))
                    .withLogConsumer(new Slf4jLogConsumer(logger))
                    .withProviderClassesFrom("target/classes")) {
                keycloak.start();

                createFederation(keycloak);
                createBrowserClient(keycloak);
                wireAuthenticator(keycloak);

                // Baseline (LDAP up): login succeeds (302 to redirect_uri) and imports the user.
                LoginResult ok = login(keycloak, "outageuser", "secret123");
                assertEquals(302, ok.status(),
                        "baseline login should redirect on success; body=" + snippet(ok.body()));
                Map<String, Object> before = getUser(keycloak, "outageuser");
                assertNotNull(before, "user imported");
                String idBefore = (String) before.get("id");

                // Outage: pause the LDAP container.
                DockerClientFactory.instance().client().pauseContainerCmd(openldap.getContainerId()).exec();
                LoginResult outage;
                try {
                    outage = login(keycloak, "outageuser", "secret123");
                } finally {
                    DockerClientFactory.instance().client().unpauseContainerCmd(openldap.getContainerId()).exec();
                }
                assertEquals(200, outage.status(), "outage login re-renders the form (not a 500)");
                assertTrue(outage.body().toLowerCase().contains("temporarily unavailable"),
                        "outage login shows the service-unavailable message");
                assertTrue(!outage.body().contains("Invalid username or password"),
                        "outage login must NOT show the misleading invalid-credentials message");

                // No purge: same imported record survives the outage.
                Map<String, Object> after = null;
                for (int i = 0; i < 15 && after == null; i++) {
                    try {
                        after = getUser(keycloak, "outageuser");
                    } catch (IOException e) {
                        Thread.sleep(2000);
                    }
                }
                assertNotNull(after, "imported user must not be purged");
                assertEquals(idBefore, after.get("id"), "same local record after outage");
            }
        }
    }
}
