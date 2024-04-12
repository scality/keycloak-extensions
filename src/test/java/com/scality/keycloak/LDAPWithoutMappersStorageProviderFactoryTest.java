package com.scality.keycloak;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;

public class LDAPWithoutMappersStorageProviderFactoryTest {
    private Logger logger = LoggerFactory.getLogger(LDAPWithoutMappersStorageProviderFactoryTest.class);
    private TokenProvider tokenProvider = new TokenProvider();

    private List<ComponentRepresentation> getMappers(KeycloakContainer keycloak, String providerId) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/components?parent=" + providerId
                + "&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            System.out.println("Get Mappers responseCode = " + responseCode);
            InputStream errorStream = conn.getErrorStream();
            if (errorStream != null) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = errorStream.read(buffer)) != -1) {
                    System.out.write(buffer, 0, bytesRead);
                }
            }
        }
        String responsePayload = IOUtils.toString(conn.getInputStream(), "UTF-8");
        TypeReference<List<ComponentRepresentation>> type = new TypeReference<List<ComponentRepresentation>>() {
        };
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(responsePayload, type);
    }

    private String createLdapConfiguration(KeycloakContainer keycloak) throws IOException {
        /// Retrieve Master realm id
        URL urlMasterRealm = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master");
        HttpURLConnection connMasterRealm = (HttpURLConnection) urlMasterRealm.openConnection();
        connMasterRealm.setRequestMethod("GET");
        connMasterRealm.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
        int responseCodeMasterRealm = connMasterRealm.getResponseCode();
        if (responseCodeMasterRealm != 200) {
            System.out.println("Get Master Realm responseCode = " + responseCodeMasterRealm);
            InputStream errorStream = connMasterRealm.getErrorStream();
            if (errorStream != null) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = errorStream.read(buffer)) != -1) {
                    System.out.write(buffer, 0, bytesRead);
                }
            }
        }
        String responsePayloadMasterRealm = IOUtils.toString(connMasterRealm.getInputStream(), "UTF-8");
        // Todo parse json
        String masterRealmId = responsePayloadMasterRealm.substring(responsePayloadMasterRealm.indexOf("id") + 5,
                responsePayloadMasterRealm.indexOf("realm") - 3);

        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/components");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.getOutputStream().write(
                ("{\n" + //
                        "  \"config\": {\n" + //
                        "    \"enabled\": [\n" + //
                        "      \"true\"\n" + //
                        "    ],\n" + //
                        "    \"vendor\": [\n" + //
                        "      \"other\"\n" + //
                        "    ],\n" + //
                        "    \"connectionUrl\": [\n" + //
                        "      \"ldap://ldap.local\"\n" + //
                        "    ],\n" + //
                        "    \"bindDn\": [\n" + //
                        "      \"cn=admin,dc=ldap,dc=local\"\n" + //
                        "    ],\n" + //
                        "    \"bindCredential\": [\n" + //
                        "      \"password\"\n" + //
                        "    ],\n" + //
                        "    \"startTls\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"authType\": [\n" + //
                        "      \"simple\"\n" + //
                        "    ],\n" + //
                        "    \"usersDn\": [\n" + //
                        "      \"ou=people,dc=ldap,dc=local\"\n" + //
                        "    ],\n" + //
                        "    \"usernameLDAPAttribute\": [\n" + //
                        "      \"cn\"\n" + //
                        "    ],\n" + //
                        "    \"rdnLDAPAttribute\": [\n" + //
                        "      \"uid\"\n" + //
                        "    ],\n" + //
                        "    \"uuidLDAPAttribute\": [\n" + //
                        "      \"entryUUID\"\n" + //
                        "    ],\n" + //
                        "    \"userObjectClasses\": [\n" + //
                        "      \"person\"\n" + //
                        "    ],\n" + //
                        "    \"customUserSearchFilter\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"searchScope\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"allowKerberosAuthentication\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"connectionTimeout\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"useTruststoreSpi\": [\n" + //
                        "      \"always\"\n" + //
                        "    ],\n" + //
                        "    \"connectionPooling\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"readTimeout\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"editMode\": [\n" + //
                        "      \"UNSYNCED\"\n" + //
                        "    ],\n" + //
                        "    \"batchSizeForSync\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"importEnabled\": [\n" + //
                        "      \"true\"\n" + //
                        "    ],\n" + //
                        "    \"syncRegistrations\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"useKerberosForPasswordAuthentication\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"cachePolicy\": [\n" + //
                        "      \"DEFAULT\"\n" + //
                        "    ],\n" + //
                        "    \"usePasswordModifyExtendedOp\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"validatePasswordPolicy\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"trustEmail\": [\n" + //
                        "      \"true\"\n" + //
                        "    ],\n" + //
                        "    \"changedSyncPeriod\": [\n" + //
                        "      \"-1\"\n" + //
                        "    ],\n" + //
                        "    \"fullSyncPeriod\": [\n" + //
                        "      \"-1\"\n" + //
                        "    ],\n" + //
                        "    \"pagination\": [\n" + //
                        "      \"false\"\n" + //
                        "    ]\n" + //
                        "  },\n" + //
                        "  \"providerId\": \"ldap-without-mappers\",\n" + //
                        "  \"providerType\": \"org.keycloak.storage.UserStorageProvider\",\n" + //
                        "  \"parentId\": \"" + masterRealmId + "\",\n" + //
                        "  \"name\": \"ldap\"\n" + //
                        "}").getBytes());
        conn.getOutputStream().close();
        String location = conn.getHeaderField("Location");
        conn.getInputStream().close();
        String providerID = location.substring(location.lastIndexOf('/') + 1);

        return providerID;
    }

    @Test
    public void should_not_create_mappers()
            throws IOException, UnsupportedOperationException, InterruptedException {
        Network network = Network.newNetwork();

        try (KeycloakContainer keycloak = FullImageName.createContainer()
                .withNetwork(network)
                .withStartupTimeout(Duration.ofMinutes(5))
                .withLogConsumer(new Slf4jLogConsumer(logger))
                .withProviderClassesFrom("target/classes")) {
            keycloak.start();

            String providerId = createLdapConfiguration(keycloak);
            List<ComponentRepresentation> mappers = getMappers(keycloak, providerId);

            assertEquals(0, mappers.size());
        }

    }
}
