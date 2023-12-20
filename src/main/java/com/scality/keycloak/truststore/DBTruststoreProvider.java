package com.scality.keycloak.truststore;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.HostnameVerificationPolicy;
import org.keycloak.truststore.JSSETruststoreConfigurator;
import org.keycloak.truststore.TruststoreProvider;

public class DBTruststoreProvider implements TruststoreProvider {

    private static final Logger logger = Logger.getLogger(DBTruststoreProvider.class);

    private KeycloakSession session;

    private SSLSocketFactory sslSocketFactory;

    public DBTruststoreProvider(KeycloakSession session) {
        this.session = session;
        SSLSocketFactory jsseSSLSocketFactory = new JSSETruststoreConfigurator(this).getSSLSocketFactory();
        this.sslSocketFactory = (jsseSSLSocketFactory != null) ? jsseSSLSocketFactory
                : (SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
    }

    @Override
    public void close() {
        // nothing to close
    }

    @Override
    public HostnameVerificationPolicy getPolicy() {
        return HostnameVerificationPolicy.WILDCARD;// Todo: make configurable
    }

    @Override
    public SSLSocketFactory getSSLSocketFactory() {
        return sslSocketFactory;
    }

    @Override
    public KeyStore getTruststore() {
        try {
            KeyStore ks = KeyStore.getInstance("jks");
            CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
            CertificateRepresentation[] certs = provider.getCertificates();
            for (CertificateRepresentation cert : certs) {
                ks.setCertificateEntry(cert.alias(), provider.toX509Certificate(cert));
            }

            return ks;
        } catch (KeyStoreException e) {
            logger.error("Error while loading truststore", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Map<X500Principal, X509Certificate> getRootCertificates() {
        CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
        CertificateRepresentation[] rootCerts = provider.getCertificates(true);
        return Stream.of(rootCerts).map(provider::toX509Certificate)
                .collect(Collectors.toMap(X509Certificate::getSubjectX500Principal, cert -> cert));
    }

    @Override
    public Map<X500Principal, X509Certificate> getIntermediateCertificates() {
        CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
        CertificateRepresentation[] rootCerts = provider.getCertificates(false);
        return Stream.of(rootCerts).map(provider::toX509Certificate)
                .collect(Collectors.toMap(X509Certificate::getSubjectX500Principal, cert -> cert));
    }

}
