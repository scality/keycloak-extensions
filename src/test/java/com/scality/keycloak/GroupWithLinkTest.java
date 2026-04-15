package com.scality.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.HashMap;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.MountableFile;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scality.keycloak.groupFederationLink.GroupWithLinkRepresentation;

import dasniko.testcontainers.keycloak.KeycloakContainer;

record ProviderAndMapper(String providerID, String mapperID) {
}

public class GroupWithLinkTest {

    private final Logger logger = LoggerFactory.getLogger(GroupWithLinkTest.class);
    private final TokenProvider tokenProvider = new TokenProvider();

    private ProviderAndMapper createLdapConfigurationAndLdapGroupMapper(KeycloakContainer keycloak) throws IOException {
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
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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

    private Long countGroupsWithLink(KeycloakContainer keycloak, String federationLink) throws IOException {
        URL url = new URL(
                keycloak.getAuthServerUrl() + "/admin/realms/master/groups-with-link/count?link="
                        + federationLink);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));

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
            return 0L;
        }

        String responsePayload = IOUtils.toString(conn.getInputStream(), "UTF-8");
        ObjectMapper objectMapper = new ObjectMapper();
        TypeReference<HashMap<String, Long>> typeRef = new TypeReference<HashMap<String, Long>>() {
        };
        Map<String, Long> result = objectMapper.readValue(responsePayload, typeRef);
        return result.get("count");
    }

    private Stream<GroupWithLinkRepresentation> getGroupsWithLink(KeycloakContainer keycloak, String federationLink,
            String search)
            throws IOException {
        URL url = new URL(
                keycloak.getAuthServerUrl() + "/admin/realms/master/groups-with-link?link=" + federationLink
                        + "&search=" + search);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));

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

    private GroupWithLinkRepresentation findGroupWithLink(KeycloakContainer keycloak, String id)
            throws IOException {
        URL url = new URL(
                keycloak.getAuthServerUrl() + "/admin/realms/master/groups-with-link/" + id);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));

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
        // parse responsePayload JSON to GroupWithLinkRepresentation
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(responsePayload, GroupWithLinkRepresentation.class);
    }

    private int deleteComponent(KeycloakContainer keycloak, String componentId) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/components/" + componentId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("DELETE");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
        return conn.getResponseCode();
    }

    private int deleteGroup(KeycloakContainer keycloak, String groupId) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/groups/" + groupId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("DELETE");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
        return conn.getResponseCode();
    }

    private List<Map<String, Object>> listRealmGroups(KeycloakContainer keycloak) throws IOException {
        URL url = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/groups");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
        String responsePayload = IOUtils.toString(conn.getInputStream(), "UTF-8");
        ObjectMapper objectMapper = new ObjectMapper();
        TypeReference<List<Map<String, Object>>> typeRef = new TypeReference<List<Map<String, Object>>>() {
        };
        return objectMapper.readValue(responsePayload, typeRef);
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
                connLocalGroup.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
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

                Long count = countGroupsWithLink(keycloak, providerAndMapper.providerID());
                Long expectedLong = 1L;
                assertEquals(expectedLong, count);
            }
        }

    }

    @Test
    public void group_with_link_should_be_returned_when_findGroup()
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

                // get the id of the ldap group
                Stream<GroupWithLinkRepresentation> groupsWithLink = getGroupsWithLink(keycloak, "", "");
                String ldapGroupId = groupsWithLink.findFirst().get().getId();
                // V
                GroupWithLinkRepresentation groupWithLink = findGroupWithLink(keycloak, ldapGroupId);
                assertEquals(providerAndMapper.providerID(), groupWithLink.getFederationLink());
                assertEquals(ldapGroupId, groupWithLink.getId());
                assertTrue(groupWithLink.getName().startsWith("myGroup"));

            }
        }
    }

    @Test
    public void group_with_link_should_return_non_ldap_group_when_findGroup()
            throws IOException, UnsupportedOperationException, InterruptedException {
        Network network = Network.newNetwork();
        // S

        // Create some Keycloak groups
        try (KeycloakContainer keycloak = FullImageName.createContainer()
                .withNetwork(network)
                .withStartupTimeout(Duration.ofMinutes(5))
                .withLogConsumer(new Slf4jLogConsumer(logger))
                .withProviderClassesFrom("target/classes")) {
            keycloak.start();

            // Create a local group
            URL urlLocalGroup = new URL(
                    keycloak.getAuthServerUrl() + "/admin/realms/master/groups");
            HttpURLConnection connLocalGroup = (HttpURLConnection) urlLocalGroup.openConnection();
            connLocalGroup.setRequestMethod("POST");
            connLocalGroup.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
            connLocalGroup.setRequestProperty("Content-Type", "application/json");
            connLocalGroup.setDoOutput(true);
            connLocalGroup.getOutputStream().write(
                    ("{\n" + //
                            "  \"name\": \"local-group\"\n" + //
                            "}").getBytes());
            connLocalGroup.getOutputStream().close();
            connLocalGroup.getResponseCode();

            Stream<GroupWithLinkRepresentation> groupsWithLink = getGroupsWithLink(keycloak, "", "");
            String localGroupId = groupsWithLink.findFirst().get().getId();
            // V
            GroupWithLinkRepresentation groupWithLink = findGroupWithLink(keycloak, localGroupId);
            assertEquals(null, groupWithLink.getFederationLink());
            assertEquals(localGroupId, groupWithLink.getId());
            assertEquals("local-group", groupWithLink.getName());

        }

    }

    @Test
    public void idp_deletion_cleans_groups_and_link_rows()
            throws IOException, UnsupportedOperationException, InterruptedException {
        Network network = Network.newNetwork();
        try (GenericContainer openldap = new GenericContainer<>("osixia/openldap:latest")
                .withCreateContainerCmdModifier(it -> it.withHostName("ldap.local"))
                .withNetwork(network)
                .withEnv("LDAP_DOMAIN", "ldap.local")
                .withEnv("LDAP_ADMIN_PASSWORD", "password")
                .withEnv("LDAP_TLS_VERIFY_CLIENT", "try")
                .withCopyFileToContainer(MountableFile.forClasspathResource("/sample.ldif"), "/sample.ldif")
                .withExposedPorts(389, 636)) {
            openldap.start();

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

                Long countBefore = countGroupsWithLink(keycloak, providerAndMapper.providerID());
                assertTrue(countBefore > 0, "Expected link rows to exist before IDP deletion");

                int deleteStatus = deleteComponent(keycloak, providerAndMapper.providerID());
                assertEquals(204, deleteStatus, "Expected 204 when deleting the LDAP provider");

                Long countAfter = countGroupsWithLink(keycloak, providerAndMapper.providerID());
                assertEquals(0L, countAfter, "Expected all link rows to be removed after IDP deletion");

                List<Map<String, Object>> realmGroups = listRealmGroups(keycloak);
                assertEquals(0, realmGroups.size(), "Expected realm groups to be empty after IDP deletion");
            }
        }
    }

    @Test
    public void direct_group_deletion_cleans_link_row_via_fk_cascade()
            throws IOException, UnsupportedOperationException, InterruptedException {
        Network network = Network.newNetwork();
        try (GenericContainer openldap = new GenericContainer<>("osixia/openldap:latest")
                .withCreateContainerCmdModifier(it -> it.withHostName("ldap.local"))
                .withNetwork(network)
                .withEnv("LDAP_DOMAIN", "ldap.local")
                .withEnv("LDAP_ADMIN_PASSWORD", "password")
                .withEnv("LDAP_TLS_VERIFY_CLIENT", "try")
                .withCopyFileToContainer(MountableFile.forClasspathResource("/sample.ldif"), "/sample.ldif")
                .withExposedPorts(389, 636)) {
            openldap.start();

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

                Stream<GroupWithLinkRepresentation> groupsWithLink = getGroupsWithLink(keycloak, "", "");
                String ldapGroupId = groupsWithLink.findFirst().get().getId();

                Long countBefore = countGroupsWithLink(keycloak, providerAndMapper.providerID());
                assertTrue(countBefore > 0, "Expected link row to exist before group deletion");

                int deleteStatus = deleteGroup(keycloak, ldapGroupId);
                assertEquals(204, deleteStatus, "Expected 204 when deleting the group");

                Long countAfter = countGroupsWithLink(keycloak, providerAndMapper.providerID());
                assertEquals(countBefore - 1, countAfter,
                        "Expected link row count to decrease by 1 after group deletion (FK CASCADE)");
            }
        }
    }

    @Test
    public void idp_deletion_does_not_affect_non_linked_groups()
            throws IOException, UnsupportedOperationException, InterruptedException {
        Network network = Network.newNetwork();
        try (GenericContainer openldap = new GenericContainer<>("osixia/openldap:latest")
                .withCreateContainerCmdModifier(it -> it.withHostName("ldap.local"))
                .withNetwork(network)
                .withEnv("LDAP_DOMAIN", "ldap.local")
                .withEnv("LDAP_ADMIN_PASSWORD", "password")
                .withEnv("LDAP_TLS_VERIFY_CLIENT", "try")
                .withCopyFileToContainer(MountableFile.forClasspathResource("/sample.ldif"), "/sample.ldif")
                .withExposedPorts(389, 636)) {
            openldap.start();

            openldap.execInContainer("ldapmodify", "-x", "-D",
                    "cn=admin,dc=ldap,dc=local", "-w", "password", "-H",
                    "ldap://ldap.local", "-f", "/sample.ldif");

            try (KeycloakContainer keycloak = FullImageName.createContainer()
                    .withNetwork(network)
                    .withStartupTimeout(Duration.ofMinutes(5))
                    .withLogConsumer(new Slf4jLogConsumer(logger))
                    .withProviderClassesFrom("target/classes")) {
                keycloak.start();

                URL urlLocalGroup = new URL(keycloak.getAuthServerUrl() + "/admin/realms/master/groups");
                HttpURLConnection connLocalGroup = (HttpURLConnection) urlLocalGroup.openConnection();
                connLocalGroup.setRequestMethod("POST");
                connLocalGroup.setRequestProperty("Authorization", "Bearer " + tokenProvider.getToken(keycloak));
                connLocalGroup.setRequestProperty("Content-Type", "application/json");
                connLocalGroup.setDoOutput(true);
                connLocalGroup.getOutputStream().write(("{\"name\": \"local-group\"}").getBytes());
                connLocalGroup.getOutputStream().close();
                connLocalGroup.getResponseCode();

                ProviderAndMapper providerAndMapper = createLdapConfigurationAndLdapGroupMapper(keycloak);
                syncLdapGroups(keycloak, providerAndMapper);

                List<Map<String, Object>> groupsBefore = listRealmGroups(keycloak);
                assertTrue(groupsBefore.size() >= 2, "Expected at least a local group and an LDAP group");

                int deleteStatus = deleteComponent(keycloak, providerAndMapper.providerID());
                assertEquals(204, deleteStatus, "Expected 204 when deleting the LDAP provider");

                List<Map<String, Object>> groupsAfter = listRealmGroups(keycloak);
                assertEquals(1, groupsAfter.size(), "Expected only the local group to remain after IDP deletion");
                assertEquals("local-group", groupsAfter.get(0).get("name"),
                        "Expected the remaining group to be the local group");
            }
        }
    }
}
