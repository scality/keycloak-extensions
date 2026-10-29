package com.scality.keycloak.longLivedToken;

public record LongLivedTokenRequest(Long lifespan, String label) {

}
