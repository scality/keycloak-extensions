package com.scality.keycloak.longLivedToken;

public record LongLivedTokenResponse(String token, String jti, long exp) {

}
