package com.scality.keycloak;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
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
                .withStartupTimeout(Duration.ofMinutes(5))
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

    private List<CertificateRepresentation> getCertificates(KeycloakContainer keycloak) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/certificates");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        ObjectMapper objectMapper = new ObjectMapper();
        List<CertificateRepresentation> certificates = objectMapper.readValue(conn.getInputStream(),
                new TypeReference<>() {
                });
        return certificates;
    }

    private HttpURLConnection addCertificateConnection(KeycloakContainer keycloak, String alias, String certificate)
            throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/certificates");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.getOutputStream().write(("{\n" + //
                "    \"alias\": \"" + alias + "\",\n" + //
                "    \"certificate\": \"" + certificate + "\"\n" +
                "}").getBytes());
        return conn;
    }

    private CertificateRepresentation upsertCertificateConnection(KeycloakContainer keycloak, String alias,
            String certificate)
            throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/certificates/" + alias);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("PUT");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.getOutputStream().write(("{\n" + //
                "    \"certificate\": \"" + certificate + "\"\n" +
                "}").getBytes());
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(conn.getInputStream(), CertificateRepresentation.class);
    }

    private void removeCertificateConnection(KeycloakContainer keycloak, String alias) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/certificates/" + alias);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("DELETE");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        conn.getResponseCode();
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
            Container.ExecResult base64CaResult = openldap.execInContainer("base64", "-w", "0",
                    "/container/service/slapd/assets/certs/ca.crt");
            String base64Ca = base64CaResult.getStdout();

            try (KeycloakContainer keycloak = FullImageName.createContainer()
                    .withNetwork(network)
                    .withStartupTimeout(Duration.ofMinutes(5))
                    .withLogConsumer(new Slf4jLogConsumer(logger))
                    .withProviderClassesFrom("target/classes")) {
                keycloak.start();

                // E
                String alias = "ldap.local";
                // Post on certificates endpoint to trust the CA
                HttpURLConnection conn = addCertificateConnection(keycloak, alias, base64Ca);
                int responseCode = conn.getResponseCode();

                // V
                assertTrue(responseCode == 204);
                assertTrue(isLDAPWithStartTlsConnectionWorking(keycloak));

                // V
                List<CertificateRepresentation> certificates = getCertificates(keycloak);

                assertFalse(certificates.isEmpty());
                assertTrue(certificates.stream().anyMatch(it -> it.alias().equals("ldap.local")));

                // E
                removeCertificateConnection(keycloak, alias);
                CertificateRepresentation upsertedCertificate = upsertCertificateConnection(keycloak, alias, base64Ca);
                assertEquals("docker-light-baseimage", upsertedCertificate.commonName());
            }
        }

    }

}
