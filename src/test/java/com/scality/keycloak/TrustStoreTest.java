package com.scality.keycloak;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import org.junit.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.shaded.org.apache.commons.io.IOUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scality.keycloak.truststore.CertificateRepresentation;

import dasniko.testcontainers.keycloak.KeycloakContainer;

public class TrustStoreTest {

    private Logger logger = LoggerFactory.getLogger(TrustStoreTest.class);

    @Test
    public void truststore_provider_should_be_registered() throws IOException {
        try (KeycloakContainer keycloak = FullImageName.createContainer()
                .withProviderClassesFrom("target/classes")) {
            keycloak.start();

            ObjectMapper objectMapper = new ObjectMapper();

            URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/certificates");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));

            List<CertificateRepresentation> certificates = objectMapper.readValue(conn.getInputStream(),
                    new TypeReference<>() {
                    });
            assertTrue(certificates.isEmpty());
        }

    }

    private String getToken(KeycloakContainer keycloak) {
        Keycloak keycloakClient = keycloak.getKeycloakAdminClient();
        AccessTokenResponse accessTokenResponse = keycloakClient.tokenManager().getAccessToken();
        return accessTokenResponse.getToken();
    }

    private Boolean isLDAPWithStartTlsConnectionWorking(KeycloakContainer keycloak) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/testLDAPConnection");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.getOutputStream().write(("{\n" + //
                "    \"connectionUrl\": \"ldap://ldap.local\",\n" + //
                "    \"bindDn\": \"\",\n" + //
                "    \"bindCredential\": \"\",\n" + //
                "    \"useTruststoreSpi\": \"always\",\n" + //
                "    \"connectionTimeout\": \"\",\n" + //
                "    \"startTls\": \"true\",\n" + //
                "    \"authType\": \"simple\",\n" + //
                "    \"action\": \"testConnection\"\n" + //
                "}").getBytes());
        int responseCode = conn.getResponseCode();

        if (responseCode != 204) {
            System.out.println("responseCode = " + responseCode);
            IOUtils.copy(conn.getErrorStream(), System.out);
        }
        return responseCode == 204;
    }

    private HttpURLConnection getCertificatesConnection(KeycloakContainer keycloak) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/certificates");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        return conn;
    }

    private HttpURLConnection addCertificateConnection(KeycloakContainer keycloak) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/certificates");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        return conn;
    }

    @Test
    public void truststore_provider_should_be_taken_in_account_when_setup_ldap()
            throws IOException, UnsupportedOperationException, InterruptedException {
        Network network = Network.newNetwork();
        // S
        try (GenericContainer openldap = new GenericContainer<>("osixia/openldap:latest")
                .withCreateContainerCmdModifier(it -> it.withHostName("ldap.local"))
                .withNetwork(network)
                .withEnv("LDAP_ORGANISATION", "Scality")
                .withEnv("LDAP_DOMAIN", "ldap.local")
                .withEnv("LDAP_ADMIN_PASSWORD", "password")
                .withEnv("LDAP_TLS_VERIFY_CLIENT", "try")
                .withExposedPorts(389, 636)) {
            openldap.start();

            try (KeycloakContainer keycloak = FullImageName.createContainer()
                    .withNetwork(network)
                    .withLogConsumer(new Slf4jLogConsumer(logger))
                    .withProviderClassesFrom("target/classes")) {
                keycloak.start();

                // V
                assertFalse(isLDAPWithStartTlsConnectionWorking(keycloak));

                // E
                Container.ExecResult base64CaResult = openldap.execInContainer("base64", "-w", "0",
                        "/container/service/slapd/assets/certs/ca.crt");
                String base64Ca = base64CaResult.getStdout();

                // Post on certificates endpoint to trust the CA
                HttpURLConnection conn = addCertificateConnection(keycloak);
                conn.getOutputStream().write(("{\n" + //
                        "    \"alias\": \"ldap.local\",\n" + //
                        "    \"certificate\": \"" + base64Ca + "\"\n" +
                        "}").getBytes());
                int responseCode = conn.getResponseCode();

                // V
                assertTrue(responseCode == 204);
                assertTrue(isLDAPWithStartTlsConnectionWorking(keycloak));

                // V
                conn = getCertificatesConnection(keycloak);
                ObjectMapper objectMapper = new ObjectMapper();
                List<CertificateRepresentation> certificates = objectMapper.readValue(conn.getInputStream(),
                        new TypeReference<>() {
                        });
                assertFalse(certificates.isEmpty());
                assertTrue(certificates.stream().anyMatch(it -> it.alias().equals("ldap.local")));
            }
        }

    }

}
