package com.scality.keycloak;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.stream.Stream;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.MountableFile;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scality.keycloak.groupFederationLink.GroupWithLinkRepresentation;

import dasniko.testcontainers.keycloak.KeycloakContainer;

record ProviderAndMapper(String providerID, String mapperID) {
}

public class GroupWithLinkTest {

    private Logger logger = LoggerFactory.getLogger(GroupWithLinkTest.class);

    private String getToken(KeycloakContainer keycloak) {
        Keycloak keycloakClient = keycloak.getKeycloakAdminClient();
        AccessTokenResponse accessTokenResponse = keycloakClient.tokenManager().getAccessToken();
        return accessTokenResponse.getToken();
    }

    private ProviderAndMapper createLdapConfigurationAndLdapGroupMapper(KeycloakContainer keycloak) throws IOException {
        /// Retrieve Master realm id
        URL urlMasterRealm = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master");
        HttpURLConnection connMasterRealm = (HttpURLConnection) urlMasterRealm.openConnection();
        connMasterRealm.setRequestMethod("GET");
        connMasterRealm.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
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
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
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
                        "  \"providerId\": \"ldap\",\n" + //
                        "  \"providerType\": \"org.keycloak.storage.UserStorageProvider\",\n" + //
                        "  \"parentId\": \"" + masterRealmId + "\",\n" + //
                        "  \"name\": \"ldap\"\n" + //
                        "}").getBytes());
        conn.getOutputStream().close();
        String location = conn.getHeaderField("Location");
        conn.getInputStream().close();
        String providerID = location.substring(location.lastIndexOf('/') + 1);

        url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/components");
        conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.getOutputStream().write(
                ("{\n" + //
                        "  \"name\": \"groups\",\n" + //
                        "  \"parentId\": \"" + providerID + "\",\n" + //
                        "  \"providerType\": \"org.keycloak.storage.ldap.mappers.LDAPStorageMapper\",\n" + //
                        "  \"providerId\": \"group-with-link-ldap-mapper\",\n" + //
                        "  \"config\": {\n" + //
                        "    \"groups.dn\": [\n" + //
                        "      \"ou=groups,dc=ldap,dc=local\"\n" + //
                        "    ],\n" + //
                        "    \"group.name.ldap.attribute\": [\n" + //
                        "      \"cn\"\n" + //
                        "    ],\n" + //
                        "    \"group.object.classes\": [\n" + //
                        "      \"groupOfNames\"\n" + //
                        "    ],\n" + //
                        "    \"preserve.group.inheritance\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"ignore.missing.groups\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"membership.ldap.attribute\": [\n" + //
                        "      \"member\"\n" + //
                        "    ],\n" + //
                        "    \"membership.attribute.type\": [\n" + //
                        "      \"DN\"\n" + //
                        "    ],\n" + //
                        "    \"membership.user.ldap.attribute\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"groups.ldap.filter\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"mode\": [\n" + //
                        "      \"READ_ONLY\"\n" + //
                        "    ],\n" + //
                        "    \"user.roles.retrieve.strategy\": [\n" + //
                        "      \"LOAD_GROUPS_BY_MEMBER_ATTRIBUTE\"\n" + //
                        "    ],\n" + //
                        "    \"memberof.ldap.attribute\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"mapped.group.attributes\": [\n" + //
                        "      \"\"\n" + //
                        "    ],\n" + //
                        "    \"drop.non.existing.groups.during.sync\": [\n" + //
                        "      \"false\"\n" + //
                        "    ],\n" + //
                        "    \"groups.path\": [\n" + //
                        "      \"/\"\n" + //
                        "    ]\n" + //
                        "  }\n" + //
                        "}").getBytes());
        conn.getOutputStream().close();
        location = conn.getHeaderField("Location");
        conn.getInputStream().close();
        String mapperID = location.substring(location.lastIndexOf('/') + 1);

        return new ProviderAndMapper(providerID, mapperID);
    }

    private void syncLdapGroups(KeycloakContainer keycloak, ProviderAndMapper providerAndMapper) throws IOException {
        URL url = new URL(
                keycloak.getAuthServerUrl() + "/admin/realms/master/user-storage/" + providerAndMapper.providerID()
                        + "/mappers/" + providerAndMapper.mapperID() + "/sync?direction=fedToKeycloak");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.getOutputStream().write("{}".getBytes());

        int responseCode = conn.getResponseCode();

        if (responseCode != 200) {
            System.out.println("Sync responseCode = " + responseCode);
            InputStream errorStream = conn.getErrorStream();
            if (errorStream != null) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = errorStream.read(buffer)) != -1) {
                    System.out.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    private Stream<GroupWithLinkRepresentation> getGroupsWithLink(KeycloakContainer keycloak, String federationLink,
            String search)
            throws IOException {
        URL url = new URL(
                keycloak.getAuthServerUrl() + "/admin/realms/master/groups-with-link?link=" + federationLink
                        + "&search=" + search);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));

        int responseCode = conn.getResponseCode();

        if (responseCode != 200) {
            System.out.println("responseCode = " + responseCode);
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
        // parse responsePayload JSON to Stream<GroupWithLinkRepresentation>
        ObjectMapper objectMapper = new ObjectMapper();
        GroupWithLinkRepresentation[] groupWithLinkRepresentations = objectMapper.readValue(responsePayload,
                GroupWithLinkRepresentation[].class);
        return Stream.of(groupWithLinkRepresentations);

    }

    @Test
    public void groups_with_links_should_be_returned_when_listing_groups()
            throws IOException, UnsupportedOperationException, InterruptedException {
        Network network = Network.newNetwork();
        // S
        try (GenericContainer openldap = new GenericContainer<>("osixia/openldap:latest")
                .withCreateContainerCmdModifier(it -> it.withHostName("ldap.local"))
                .withNetwork(network)
                .withEnv("LDAP_DOMAIN", "ldap.local")
                .withEnv("LDAP_ADMIN_PASSWORD", "password")
                .withEnv("LDAP_TLS_VERIFY_CLIENT", "try")
                .withCopyFileToContainer(MountableFile.forClasspathResource("/sample.ldif"), "/sample.ldif")
                .withExposedPorts(389, 636)) {
            openldap.start();

            // Create some LDAP groups
            openldap.execInContainer("ldapmodify", "-x", "-D",
                    "cn=admin,dc=ldap,dc=local", "-w", "password", "-H",
                    "ldap://ldap.local", "-f", "/sample.ldif");

            try (KeycloakContainer keycloak = FullImageName.createContainer()
                    .withNetwork(network)
                    .withStartupTimeout(Duration.ofMinutes(5))
                    .withLogConsumer(new Slf4jLogConsumer(logger))
                    .withProviderClassesFrom("target/classes")) {
                keycloak.start();

                ProviderAndMapper providerAndMapper = createLdapConfigurationAndLdapGroupMapper(keycloak);
                syncLdapGroups(keycloak, providerAndMapper);

                // V
                Stream<GroupWithLinkRepresentation> groupsWithLink = getGroupsWithLink(keycloak, "", "");

                assertEquals(providerAndMapper.providerID(), groupsWithLink.findFirst().get().getFederationLink());

                // E
                // Create a local group
                URL urlLocalGroup = new URL(
                        keycloak.getAuthServerUrl() + "/admin/realms/master/groups");
                HttpURLConnection connLocalGroup = (HttpURLConnection) urlLocalGroup.openConnection();
                connLocalGroup.setRequestMethod("POST");
                connLocalGroup.setRequestProperty("Authorization", "Bearer " + getToken(keycloak));
                connLocalGroup.setRequestProperty("Content-Type", "application/json");
                connLocalGroup.setDoOutput(true);
                connLocalGroup.getOutputStream().write(
                        ("{\n" + //
                                "  \"name\": \"local-group\"\n" + //
                                "}").getBytes());
                connLocalGroup.getOutputStream().close();
                connLocalGroup.getResponseCode();

                // V
                groupsWithLink = getGroupsWithLink(keycloak, "", "");
                System.out.println(groupsWithLink);
                assertEquals(2, groupsWithLink.count());

                groupsWithLink = getGroupsWithLink(keycloak, providerAndMapper.providerID(), "");
                System.out.println(groupsWithLink);
                assertEquals(1, groupsWithLink.count());

                groupsWithLink = getGroupsWithLink(keycloak, providerAndMapper.providerID(), "myGroup1");
                System.out.println(groupsWithLink);
                assertEquals(0, groupsWithLink.count());
            }
        }

    }

}
