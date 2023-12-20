package com.scality.keycloak.truststore;

public record CertificateRepresentation(String id, String alias, String certificate, Boolean isRootCA) {

}
