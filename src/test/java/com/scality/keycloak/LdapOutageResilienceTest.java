package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

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
 * Behavioural test for RING-54200: when the LDAP server is unreachable, the login path must return
 * the generic "invalid credentials" outcome (HTTP 401) instead of a raw HTTP 500, and it must not
 * purge already-imported users.
 */
public class LdapOutageResilienceTest {
    private final Logger logger = LoggerFactory.getLogger(LdapOutageResilienceTest.class);
    private final TokenProvider tokenProvider = new TokenProvider();
    private final ObjectMapper mapper = new ObjectMapper();

    private String masterRealmId(KeycloakContainer kc) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(kc.getAuthServerUrl() + "/admin/realms/master").openConnection();
        c.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(kc));
        Map<String, Object> realm = mapper.readValue(IOUtils.toString(c.getInputStream(), "UTF-8"),
                new TypeReference<Map<String, Object>>() {
                });
        return (String) realm.get("id");
    }

    private String createFederation(KeycloakContainer kc) throws IOException {
        String parent = masterRealmId(kc);
        HttpURLConnection c = (HttpURLConnection) new URL(kc.getAuthServerUrl() + "/admin/realms/master/components")
                .openConnection();
        c.setRequestMethod("POST");
        c.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(kc));
        c.setRequestProperty("Content-Type", "application/json");
        c.setDoOutput(true);
        String body = "{\"name\":\"ldap\",\"providerId\":\"ldap-without-mappers\","
                + "\"providerType\":\"org.keycloak.storage.UserStorageProvider\",\"parentId\":\"" + parent + "\","
                + "\"config\":{"
                + "\"enabled\":[\"true\"],\"vendor\":[\"other\"],\"connectionUrl\":[\"ldap://ldap.local\"],"
                + "\"bindDn\":[\"cn=admin,dc=ldap,dc=local\"],\"bindCredential\":[\"password\"],\"authType\":[\"simple\"],"
                + "\"usersDn\":[\"ou=people,dc=ldap,dc=local\"],\"usernameLDAPAttribute\":[\"uid\"],"
                + "\"rdnLDAPAttribute\":[\"uid\"],\"uuidLDAPAttribute\":[\"entryUUID\"],"
                + "\"userObjectClasses\":[\"inetOrgPerson\"],\"searchScope\":[\"1\"],\"editMode\":[\"UNSYNCED\"],"
                + "\"importEnabled\":[\"true\"],\"cachePolicy\":[\"NO_CACHE\"],"
                + "\"connectionTimeout\":[\"\"],\"readTimeout\":[\"\"],\"pagination\":[\"false\"]}}";
        c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
        c.getOutputStream().close();
        assertEquals(201, c.getResponseCode(), "federation create");
        String location = c.getHeaderField("Location");
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private void addUsernameMapper(KeycloakContainer kc, String fedId) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(kc.getAuthServerUrl() + "/admin/realms/master/components")
                .openConnection();
        c.setRequestMethod("POST");
        c.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(kc));
        c.setRequestProperty("Content-Type", "application/json");
        c.setDoOutput(true);
        String body = "{\"name\":\"username\",\"providerId\":\"user-attribute-ldap-mapper\","
                + "\"providerType\":\"org.keycloak.storage.ldap.mappers.LDAPStorageMapper\",\"parentId\":\"" + fedId + "\","
                + "\"config\":{\"user.model.attribute\":[\"username\"],\"ldap.attribute\":[\"uid\"],"
                + "\"read.only\":[\"true\"],\"always.read.value.from.ldap\":[\"false\"],\"is.mandatory.in.ldap\":[\"true\"]}}";
        c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
        c.getOutputStream().close();
        assertEquals(201, c.getResponseCode(), "username mapper create");
    }

    /** Direct-access-grant login against the master realm; returns the HTTP status code. */
    private int passwordGrant(KeycloakContainer kc, String user, String pass) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(
                kc.getAuthServerUrl() + "/realms/master/protocol/openid-connect/token").openConnection();
        c.setRequestMethod("POST");
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        c.setDoOutput(true);
        String form = "grant_type=password&client_id=admin-cli"
                + "&username=" + URLEncoder.encode(user, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(pass, StandardCharsets.UTF_8);
        c.getOutputStream().write(form.getBytes(StandardCharsets.UTF_8));
        c.getOutputStream().close();
        return c.getResponseCode();
    }

    private Map<String, Object> getUser(KeycloakContainer kc, String username) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(
                kc.getAuthServerUrl() + "/admin/realms/master/users?exact=true&username=" + username).openConnection();
        c.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(kc));
        List<Map<String, Object>> users = mapper.readValue(IOUtils.toString(c.getInputStream(), "UTF-8"),
                new TypeReference<List<Map<String, Object>>>() {
                });
        return users.isEmpty() ? null : users.get(0);
    }

    @Test
    public void outage_login_returns_generic_error_and_keeps_imported_user() throws Exception {
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

                String fedId = createFederation(keycloak);
                addUsernameMapper(keycloak, fedId);

                // Baseline (LDAP up): login succeeds and the user is imported locally.
                assertEquals(200, passwordGrant(keycloak, "outageuser", "secret123"), "baseline login should succeed");
                Map<String, Object> before = getUser(keycloak, "outageuser");
                assertNotNull(before, "user should be imported");
                assertEquals(fedId, before.get("federationLink"));
                String idBefore = (String) before.get("id");

                // Outage: freeze the LDAP container so connections fail.
                DockerClientFactory.instance().client().pauseContainerCmd(openldap.getContainerId()).exec();
                try {
                    assertEquals(401, passwordGrant(keycloak, "outageuser", "secret123"),
                            "outage login of an imported user must be a generic 401, not a 500");
                    assertEquals(401, passwordGrant(keycloak, "nosuchuser", "whatever"),
                            "outage login of an unknown user must be a generic 401, not a 500");
                } finally {
                    DockerClientFactory.instance().client().unpauseContainerCmd(openldap.getContainerId()).exec();
                }

                // The imported user must survive the outage as the SAME record (not purged and re-created).
                Map<String, Object> after = null;
                for (int i = 0; i < 15 && after == null; i++) {
                    try {
                        after = getUser(keycloak, "outageuser");
                    } catch (IOException e) {
                        Thread.sleep(2000);
                    }
                }
                assertNotNull(after, "imported user must not be purged by the outage");
                assertEquals(idBefore, after.get("id"),
                        "imported user must be the same local record after the outage (not purged)");
            }
        }
    }
}
