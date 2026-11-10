package com.scality.keycloak.longLivedToken;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;

public class LongLivedTokenKeyProvider implements KeyProvider {
    private static final Logger logger = Logger.getLogger(LongLivedTokenKeyProvider.class);

    private final KeycloakSession session;
    private final ComponentModel model;
    // Keycloak creates the provider once per request and reads its keys for every token it signs
    // or verifies, so the registry is queried at most once per request.
    private List<KeyWrapper> keys;

    public LongLivedTokenKeyProvider(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
        if (!model.get(Attributes.ENABLED_KEY, true)) {
            return Stream.empty();
        }
        if (keys == null) {
            keys = loadKeys();
        }
        return keys.stream();
    }

    private List<KeyWrapper> loadKeys() {
        long priority = model.get(Attributes.PRIORITY_KEY, 0L);
        return session.getProvider(JpaConnectionProvider.class).getEntityManager()
                .createQuery("SELECT t FROM LongLivedTokenEntity t WHERE " + LongLivedTokenEntity.ACTIVE_IN_REALM
                        + " AND t.publicKey IS NOT NULL", LongLivedTokenEntity.class)
                .setParameter("realmId", model.getParentId())
                .setParameter("now", (long) Time.currentTime())
                .getResultStream()
                .map(entity -> {
                    try {
                        KeyWrapper key = LongLivedTokenSigningKeys.verificationKey(entity.getJti(),
                                entity.getAlgorithm(), entity.getPublicKey());
                        key.setProviderId(model.getId());
                        key.setProviderPriority(priority);
                        return key;
                    } catch (GeneralSecurityException | IllegalArgumentException e) {
                        logger.errorf(e, "Cannot read the public key of long-lived token %s", entity.getJti());
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();
    }
}
