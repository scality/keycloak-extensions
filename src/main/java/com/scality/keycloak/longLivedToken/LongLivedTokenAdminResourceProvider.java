package com.scality.keycloak.longLivedToken;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

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

    private int maxActiveTokens = DEFAULT_MAX_ACTIVE_TOKENS;
    private int maxActiveTokensPerClient = DEFAULT_MAX_ACTIVE_TOKENS_PER_CLIENT;

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
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
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
                maxActiveTokensPerClient);
    }

}
