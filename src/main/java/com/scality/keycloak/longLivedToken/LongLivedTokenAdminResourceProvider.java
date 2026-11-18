package com.scality.keycloak.longLivedToken;

import java.time.Duration;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.timer.TimerProvider;

import io.quarkus.runtime.configuration.DurationConverter;

public class LongLivedTokenAdminResourceProvider
        implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return this;
    }

    // Every OIDC client of the realm downloads the JWKS, which holds one key per active token.
    // An RSA-2048 key is about 500 bytes of JWK, so 20 keys add about 10 KB.
    static final int DEFAULT_MAX_ACTIVE_TOKENS = 20;

    // Two let a client rotate: issue the next token, switch the tool to it, then revoke the old one.
    static final int DEFAULT_MAX_ACTIVE_TOKENS_PER_CLIENT = 2;

    // The refresh catches what this replica did not do itself: expiries, and issuances or
    // revocations made on another replica. Expiry alerts count in days, so a minute is enough.
    static final Duration DEFAULT_METRIC_REFRESH_INTERVAL = Duration.ofMinutes(1);

    private int maxActiveTokens = DEFAULT_MAX_ACTIVE_TOKENS;
    private int maxActiveTokensPerClient = DEFAULT_MAX_ACTIVE_TOKENS_PER_CLIENT;
    private Duration metricRefreshInterval = DEFAULT_METRIC_REFRESH_INTERVAL;
    private LongLivedTokenExpiryMetric expiryMetric;

    @Override
    public void init(Scope config) {
        maxActiveTokens = config.getInt("maxActiveTokens", DEFAULT_MAX_ACTIVE_TOKENS);
        maxActiveTokensPerClient = config.getInt("maxActiveTokensPerClient", DEFAULT_MAX_ACTIVE_TOKENS_PER_CLIENT);
        if (maxActiveTokens < 1) {
            throw new IllegalArgumentException("maxActiveTokens must be at least 1, got " + maxActiveTokens);
        }
        if (maxActiveTokensPerClient < 1) {
            throw new IllegalArgumentException(
                    "maxActiveTokensPerClient must be at least 1, got " + maxActiveTokensPerClient);
        }
        String interval = config.get("metricRefreshInterval");
        if (interval != null) {
            metricRefreshInterval = DurationConverter.parseDuration(interval);
        }
        if (metricRefreshInterval.compareTo(Duration.ofSeconds(1)) < 0) {
            throw new IllegalArgumentException(
                    "metricRefreshInterval must be at least 1s, got " + metricRefreshInterval);
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        expiryMetric = new LongLivedTokenExpiryMetric();
        // The registry table exists only once the migrations have run.
        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                expiryMetric.refreshInNewTransaction(factory);
                KeycloakModelUtils.runJobInTransaction(factory, session -> session.getProvider(TimerProvider.class)
                        .scheduleTask(expiryMetric::refresh, metricRefreshInterval.toMillis(),
                                "long-lived-token-expiry-metric"));
            }
        });
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "long-lived-tokens";
    }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        return new LongLivedTokenAdminResource(session, realm, auth, adminEvent, maxActiveTokens,
                maxActiveTokensPerClient, expiryMetric);
    }

}
