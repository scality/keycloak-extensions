package com.scality.keycloak.truststore;

public record CertificateRepresentation(String alias, String certificate, String commonName) {

}
