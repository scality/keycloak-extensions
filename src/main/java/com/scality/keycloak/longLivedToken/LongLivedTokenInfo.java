package com.scality.keycloak.longLivedToken;

public record LongLivedTokenInfo(String jti, String label, long iat, long exp, boolean revoked, String createdBy) {

    static LongLivedTokenInfo of(LongLivedTokenEntity entity) {
        return new LongLivedTokenInfo(entity.getJti(), entity.getLabel(), entity.getIat(), entity.getExp(),
                entity.isRevoked(), entity.getCreatedBy());
    }
}
