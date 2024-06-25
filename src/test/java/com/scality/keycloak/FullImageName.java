package com.scality.keycloak;

import org.testcontainers.images.ImagePullPolicy;
import org.testcontainers.images.PullPolicy;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import static java.lang.module.ModuleDescriptor.Version;

import java.lang.module.ModuleDescriptor.Version;

public class FullImageName {
    enum Distribution {
        quarkus
    }

    private static final Distribution KEYCLOAK_DIST = Distribution.valueOf(
            System.getProperty("keycloak.dist", Distribution.quarkus.name()));

    // For now hardcode latest supported version to 24.0.5
    // A breaking change is introduced in 25.0.0 where
    // DefaultHostnameProviderFactory is replaced by DefaultHostnameProvider
    private static final String LATEST_VERSION = "24.0.5";
    private static final String NIGHTLY_VERSION = "nightly";
    private static final String KEYCLOAK_VERSION = System.getProperty("keycloak.version", LATEST_VERSION);

    static String get() {
        String imageName = "keycloak";

        if (!isNightlyVersion()) {
            if (!isLatestVersion()) {
                if (getParsedVersion().compareTo(Version.parse("17")) < 0) {
                    if (Distribution.quarkus.equals(KEYCLOAK_DIST)) {
                        imageName = "keycloak-x";
                    }
                }
            }
        }

        return "quay.io/keycloak/" + imageName + ":" + KEYCLOAK_VERSION;
    }

    static Boolean isNightlyVersion() {
        return NIGHTLY_VERSION.equalsIgnoreCase(KEYCLOAK_VERSION);
    }

    static Boolean isLatestVersion() {
        return LATEST_VERSION.equalsIgnoreCase(KEYCLOAK_VERSION);
    }

    static Version getParsedVersion() {
        if (isLatestVersion()) {
            return null;
        }
        return Version.parse(KEYCLOAK_VERSION);
    }

    static Distribution getDistribution() {
        return KEYCLOAK_DIST;
    }

    static KeycloakContainer createContainer() {
        String fullImage = FullImageName.get();
        ImagePullPolicy pullPolicy = PullPolicy.defaultPolicy();
        if (isLatestVersion() || isNightlyVersion()) {
            pullPolicy = PullPolicy.alwaysPull();
        }
        return new KeycloakContainer(fullImage)
                .withImagePullPolicy(pullPolicy);
    }

}
