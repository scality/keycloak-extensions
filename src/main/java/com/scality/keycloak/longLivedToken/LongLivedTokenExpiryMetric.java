package com.scality.keycloak.longLivedToken;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;

import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.MultiGauge;
import io.micrometer.core.instrument.Tags;

// One series per active long-lived token, valued at its expiry, so an alert rule can compare the
// tokens of one client. Every replica reads the shared registry and exports the same series.
class LongLivedTokenExpiryMetric {
    private static final Logger logger = Logger.getLogger(LongLivedTokenExpiryMetric.class);

    private final MultiGauge gauge = MultiGauge.builder("keycloak.long.lived.token.expiry.timestamp")
            .baseUnit("seconds")
            .description("Expiry of each long-lived token that is neither revoked nor expired, in epoch seconds")
            .register(Metrics.globalRegistry);

    // Runs after an issuance has committed, and at startup: a failure must neither turn the
    // committed request into an error, which would lose a token shown only once, nor stop Keycloak.
    // The next scheduled refresh catches up.
    void refreshInNewTransaction(KeycloakSessionFactory factory) {
        try {
            KeycloakModelUtils.runJobInTransaction(factory, this::refresh);
        } catch (RuntimeException e) {
            logger.warn("Could not refresh the long-lived token expiry metric", e);
        }
    }

    synchronized void refresh(KeycloakSession session) {
        List<Object[]> tokens = session.getProvider(JpaConnectionProvider.class).getEntityManager()
                .createQuery("SELECT r.name, c.clientId, t.jti, t.exp FROM LongLivedTokenEntity t, ClientEntity c,"
                        + " RealmEntity r WHERE c.id = t.clientId AND r.id = t.realmId"
                        + " AND t.revoked = false AND t.exp > :now", Object[].class)
                .setParameter("now", (long) Time.currentTime())
                .getResultList();
        gauge.register(tokens.stream()
                .map(token -> MultiGauge.Row.of(
                        Tags.of("realm", (String) token[0], "client_id", (String) token[1], "jti", (String) token[2]),
                        (Long) token[3]))
                .toList(), false);
    }
}
