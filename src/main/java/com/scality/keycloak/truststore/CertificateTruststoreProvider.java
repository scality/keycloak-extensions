package com.scality.keycloak.truststore;

import java.security.cert.X509Certificate;

import org.keycloak.provider.Provider;

public interface CertificateTruststoreProvider extends Provider {

    CertificateRepresentation getCertificate(String alias);

    CertificateRepresentation addCertificate(String alias, String certificate);

    CertificateRepresentation updateCertificate(String alias, String certificate);

    void removeCertificate(String alias);

    CertificateRepresentation[] getCertificates();

    CertificateRepresentation[] getCertificates(boolean isRootCA);

    X509Certificate toX509Certificate(CertificateRepresentation certificate);
}
