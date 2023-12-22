package com.scality.keycloak.truststore;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.HostnameVerificationPolicy;
import org.keycloak.truststore.JSSETruststoreConfigurator;
import org.keycloak.truststore.TruststoreProvider;

public class DBTruststoreProvider implements TruststoreProvider {

    private static final Logger logger = Logger.getLogger(DBTruststoreProvider.class);

    private KeycloakSession session;

    public DBTruststoreProvider(KeycloakSession session) {
        logger.info("DBTruststoreProvider constructor");
        this.session = session;
    }

    @Override
    public void close() {
        // nothing to close
    }

    @Override
    public HostnameVerificationPolicy getPolicy() {
        return HostnameVerificationPolicy.WILDCARD;// Todo: make configurable
    }

    private record SSLFactoryAndKeystore(SSLSocketFactory sslSocketFactory, KeyStore keystore) {

    }

    private SSLFactoryAndKeystore getSSLSocketFactoryAndKeyStore() {
        try {
            String trustStore = "truststore.jks";// todo ?
            char[] password = "some password".toCharArray();// todo ?

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream keystoreStream = DBTruststoreProvider.class.getResourceAsStream(trustStore);
            keystore.load(keystoreStream, password);
            CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
            CertificateRepresentation[] certs = provider.getCertificates();
            for (CertificateRepresentation cert : certs) {
                keystore.setCertificateEntry(cert.alias(), provider.toX509Certificate(cert));
            }
            trustManagerFactory.init(keystore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustManagers, null);
            SSLContext.setDefault(sc);

            return new SSLFactoryAndKeystore(sc.getSocketFactory(), keystore);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException
                | KeyManagementException e) {
            logger.error("Error while loading truststore", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public SSLSocketFactory getSSLSocketFactory() {
        return getSSLSocketFactoryAndKeyStore().sslSocketFactory();
    }

    @Override
    public KeyStore getTruststore() {
        return getSSLSocketFactoryAndKeyStore().keystore();
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
