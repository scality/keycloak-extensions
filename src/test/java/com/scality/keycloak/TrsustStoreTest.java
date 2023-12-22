// package com.scality.keycloak;

// import java.time.Duration;
// import java.util.Map;

// import org.junit.Test;
// import org.junit.jupiter.api.BeforeAll;
// import org.keycloak.admin.client.Keycloak;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
// import org.testcontainers.containers.output.Slf4jLogConsumer;
// import org.testcontainers.junit.jupiter.Container;
// import org.testcontainers.junit.jupiter.Testcontainers;

// import dasniko.testcontainers.keycloak.KeycloakContainer;

// @Testcontainers
// public class TrsustStoreTest {

// private static final Logger LOGGER =
// LoggerFactory.getLogger(TrsustStoreTest.class);

// private static String KEYCLOAK_AUTH_URL;

// @Container
// private static final KeycloakContainer KEYCLOAK_CONTAINER =
// FullImageName.createContainer()
// .withProviderClassesFrom("target/classes")
// .withExposedPorts(8080)
// .withLogConsumer(new Slf4jLogConsumer(LOGGER).withSeparateOutputStreams())
// .withStartupTimeout(Duration.ofSeconds(90));

// @BeforeAll
// static void setUp() {
// KEYCLOAK_AUTH_URL = KEYCLOAK_CONTAINER.getAuthServerUrl();
// LOGGER.info("Running test with Keycloak image: " + FullImageName.get());
// }

// @Test
// public void truststore_provider_should_be_registered() {
// Map<String, String> operationalInfo;
// try (Keycloak keycloakAdminClient =
// KEYCLOAK_CONTAINER.getKeycloakAdminClient()) {
// operationalInfo = keycloakAdminClient
// .serverInfo()
// .getInfo()
// .getProviders()
// .get("truststore")
// .getProviders()
// .get("file")
// .getOperationalInfo();
// }
// // assertThat(clientRoleName).isEqualTo("band and crew only");
// System.out.println(operationalInfo);
// }

// }
