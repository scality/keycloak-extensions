package com.scality.keycloak.longLivedToken;

public record LongLivedTokenRequest(String lifespan, String label) {

}
