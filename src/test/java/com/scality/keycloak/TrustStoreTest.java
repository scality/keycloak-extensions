package com.scality.keycloak;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
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
    private TokenProvider tokenProvider = new TokenProvider();

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
            conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));

            List<CertificateRepresentation> certificates = objectMapper.readValue(conn.getInputStream(),
                    new TypeReference<>() {
                    });
            assertTrue(certificates.isEmpty());
        }

    }

    private Boolean isLDAPWithStartTlsConnectionWorking(KeycloakContainer keycloak) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/testLDAPConnection");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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

                // V -- Is the LDAPS connection working once the CA is trusted?
                assertTrue(responseCode == 204);
                assertTrue(isLDAPWithStartTlsConnectionWorking(keycloak));

                // V -- Does list certificate returns the trusted CA ?
                List<CertificateRepresentation> certificates = getCertificates(keycloak);

                assertFalse(certificates.isEmpty());
                assertTrue(certificates.stream().anyMatch(it -> it.alias().equals("ldap.local")));

                // E
                removeCertificateConnection(keycloak, alias);
                // V -- Does list certificate returns the trusted CA ?
                List<CertificateRepresentation> certificatesPostDeletion = getCertificates(keycloak);
                assertTrue(certificatesPostDeletion.isEmpty());
                // E
                CertificateRepresentation upsertedCertificate = upsertCertificateConnection(keycloak, alias, base64Ca);
                // V -- Does the certificate get created?
                assertEquals("docker-light-baseimage", upsertedCertificate.commonName());
                List<CertificateRepresentation> certificatesPostUpsert = getCertificates(keycloak);
                assertFalse(certificatesPostUpsert.isEmpty());
                assertTrue(certificatesPostUpsert.stream().anyMatch(it -> it.alias().equals(alias)));

                // E -- Update the certificate
                String base64CaUpdated = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdKakNDQkE2Z0F3SUJBZ0lKQVBNS280QVhCSGlhTUEwR0NTcUdTSWIzRFFFQkN3VUFNSHd4Q3pBSkJnTlYKQkFZVEFrUkZNUkl3RUFZRFZRUUlEQWxHY21GdWEyOXVhV0V4RWpBUUJnTlZCQWNNQ1U1MWNtVnRZbVZ5WnpFVApNQkVHQTFVRUNnd0tiWGtnUTI5dGNHRnVlVEVXTUJRR0ExVUVDd3dOYlhrZ1JHVndZWEowYldWdWRERVlNQllHCkExVUVBd3dQVFhrZ2NtOXZkQ0JEUVNBeU1ERTNNQjRYRFRJeU1UQXlNVEUyTkRreE5Gb1hEVE15TVRBeE9ERTIKTkRreE5Gb3dmREVMTUFrR0ExVUVCaE1DUkVVeEVqQVFCZ05WQkFnTUNVWnlZVzVyYjI1cFlURVNNQkFHQTFVRQpCd3dKVG5WeVpXMWlaWEpuTVJNd0VRWURWUVFLREFwdGVTQkRiMjF3WVc1NU1SWXdGQVlEVlFRTERBMXRlU0JFClpYQmhjblJ0Wlc1ME1SZ3dGZ1lEVlFRRERBOU5lU0J5YjI5MElFTkJJREl3TVRjd2dnSWlNQTBHQ1NxR1NJYjMKRFFFQkFRVUFBNElDRHdBd2dnSUtBb0lDQVFEeFkrTE9wc2p0OFhiYittY3hJblBsTHN4emY0d09xaDcrYVpFWgpJR01DRzVjN1RMeklmTThIcVpCb1NVNHE1cnFpMzFwK3JrWlFiS1RGWnhBSzB0TzlNSFE0dVdMSFJlNnNLaGFUCmtmbzNRRDBybU51a0JkQ1ZvNkhXR00yY3E1WU1haHBrb0VEMmZHMVFSRjEvSk8wWWdwYVp0dTA1dVowd0dHNW4KWjFIcmxDNUZzczJ0dXRydFc1VmZtbWNNNVNUYVdwRWUwZ0gwVTdHVnNNVzliN1l6UGRQb1FUVGZSa2F2OFpEagpXWktRaFU4Umh4VE9FT2RGMzlwNnJFNzBOQ3RGNlFaNGNPV2lTVWo0eVZ6V0d3UGpuL3Z3ZXZpeFhrZ0w3cWJHClZmTzBTQ1VPZEJpSGMxR1FaVjFTdDdHd3ZtUHdmS1JzcWhTbUs2TUZ5czhBcUFUUDZxNVdMMU9CeU1LRWNud04KWnpjdG03Y2RlOVYyRFpmSU82aDhEdjM4clhxb1VNNHJFWUNKWHVZb1NQYkRSSFVlM0lKQ1VITzJoWDNuYmpKaQpGdWlXM2YvUFFQWHU0NzhxNjdXeGwrK29pWFR5dW5kalMzL3dDM1NVUDgvNzVrQUF6OUh6ZkttdzRvY0tqQnpKCnpJdi92NHI3dnhOTWI2M0dJWjRqbys5V09nazRRMU5UdVRZM0cyclVvYndZTTVxMkZxckU4R2tQSlEvL0xvSmEKK3oyQUE2ZXVxb3RNRTJ1ZHlaR29lZ0FPdTFlZ3dGTUpKUzVYckUrVU02eEZBY0JPbUhIL0RUbzF4L01BNC9Qegp1cDJCb3dpcER6UlEzelptd1U4NTFKemZSbmluMU9pNFBsTTVWK0tiSGE5dCtIVW9RWVRiYStzdE5TcGwyVHNnCnEvYUNRUUlEQVFBQm80R3FNSUduTUIwR0ExVWREZ1FXQkJSbVZWNU5QeWRNY1gyYUs1QWcrVTFWZFJOdm5qQWYKQmdOVkhTTUVHREFXZ0JSbVZWNU5QeWRNY1gyYUs1QWcrVTFWZFJOdm5qQVBCZ05WSFJNQkFmOEVCVEFEQVFILwpNQTRHQTFVZER3RUIvd1FFQXdJQkJqQkVCZ05WSFI4RVBUQTdNRG1nTjZBMWhqTm9kSFJ3T2k4dmVXOTFja1J2CmJXRnBiaTV2Y21jdlkzSnNMMmx1ZEdWeWJXVmthV0YwWldOaExXTmhMV055YkM1d1pXMHdEUVlKS29aSWh2Y04KQVFFTEJRQURnZ0lCQUlpSXdKZ2VRT1V0VE9HVkNwdlN4bTFhVVByYThOdllQSUVlR3ZZSGQ3VzYwajEzcFZIbAp2N3ZOSVRIUjBlazY1bm03VmZYR0U2VjBxcTZ1eU9JcytUSVg4R3hjYkh3Vm1rM2lWZitkNG9wemtjQmxvV3FTCkU4bTVpUWYrZXovUXk3YkRTWVRVMlFjQjBSS2NKR085Ti9uSUpQaVBFY2JFc0t1ekpmNHB5VGRaYTZKdjVRRmcKUGpza1ppdjVRRWNhM3RrVjdiMDlJMXZFb0QxcWs5Tlg4QXc3TFA1ZDlOamNFWmNWZng3d09Dcm9Kc0wwdDZLMwpMZTN5RkI5ek43enFTdkFhdmRIV2VVZUV6MUFIVEJqaS9DVDlBQTJTY3I3UlNCUzFOODRzWTRSUkVoenE3WW44CkRKLzBlNE1kbi9tcDVkQkRyNTg3dWlDdGZzeG1RZS81b1VsYzg5WVVuNlRkNVRnV2ZqRlU1ZmloWWhJZmhtVG4KcFFkNkRYTVNOYkp3VHNya3RaUi9Nd2x4cHorQ2hqY2l1TC9KemZzWS9KTk5oakJiSnd6Wk9JODhHcG1jSHo1ZQpMQ2JTMTl3NStvVjRXOUVYS3VaMGVDMHBlNm50Q0VSYjRPRHh0VytnRG4zZ0JBVGxZczNVYTJNZEZWUTU2U01OCk40ajFRajdUc0JNV2lzTmI3eUNZbndOZm5yZURKcWdtMm8vS2x5SzdzdndpbU45OUpIeGxNNnMwYlRaK3dyOEoKRFBhYlU4TVFFM1Z6bkdqaXlwVFNNQUQvcXZtVytTNUFka0U0RmpJTWdZZkdhQ0I2aHJCQkdXcWE3MENlN3ZITApKdU1lRWVNbSs4S3JFWTVoTWpMYmNHWTY3RXdiVHl0bDc2SFBSM0J5Wm03ZCt1SlJscExVN1ZxVwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==";
                CertificateRepresentation updatedCertificate = upsertCertificateConnection(keycloak, alias,
                        base64CaUpdated);
                // V -- Does the certificate get updated?
                assertEquals("My root CA 2017", updatedCertificate.commonName());
                List<CertificateRepresentation> certificatesPostUpdate = getCertificates(keycloak);
                assertTrue(certificatesPostUpdate.stream().anyMatch(it -> it.commonName().equals("My root CA 2017")));
                assertFalse(certificatesPostUpdate.stream()
                        .anyMatch(it -> it.commonName().equals("docker-light-baseimage")));
            }
        }

    }

}
