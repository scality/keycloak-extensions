package com.scality.keycloak.truststore;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.models.KeycloakSession;
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

    private KeyStore getOrCreateKeystore() {
        try {
            String trustStore = "truststore.jks";// todo ?
            char[] password = "some password".toCharArray();// todo ?

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream keystoreStream = DBTruststoreProvider.class.getResourceAsStream(trustStore);
            
            // If the resource file doesn't exist, create an empty keystore
            if (keystoreStream == null) {
                logger.debug("Truststore resource file not found, creating empty keystore");
                keystore.load(null, password);
            } else {
                keystore.load(keystoreStream, password);
            }
            
            // Add certificates from database to keystore
            CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
            CertificateRepresentation[] certs = provider.getCertificates();
            if (certs != null) {
                for (CertificateRepresentation cert : certs) {
                    keystore.setCertificateEntry(cert.alias(), provider.toX509Certificate(cert));
                }
            }
            
            return keystore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            logger.error("Error while loading truststore", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public SSLSocketFactory getSSLSocketFactory() {
        try {
            KeyStore keystore = getOrCreateKeystore();
            
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            
            // If keystore is empty, use default trust managers to avoid InvalidAlgorithmParameterException
            if (keystore.size() == 0) {
                logger.debug("Keystore is empty, using default trust managers");
                // Initialize with null to use system default truststore
                trustManagerFactory.init((KeyStore) null);
            } else {
                trustManagerFactory.init(keystore);
            }
            
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustManagers, null);
            SSLContext.setDefault(sc);

            return sc.getSocketFactory();
        } catch (KeyStoreException | NoSuchAlgorithmException | KeyManagementException e) {
            logger.error("Error while initializing SSL context", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyStore getTruststore() {
        return getOrCreateKeystore();
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getRootCertificates() {
        CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
        CertificateRepresentation[] rootCerts = provider.getCertificates(true);
        return Stream.of(rootCerts).map(provider::toX509Certificate)
                .collect(Collectors.groupingBy(X509Certificate::getSubjectX500Principal));
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getIntermediateCertificates() {
        CertificateTruststoreProvider provider = session.getProvider(CertificateTruststoreProvider.class);
        CertificateRepresentation[] rootCerts = provider.getCertificates(false);
        return Stream.of(rootCerts).map(provider::toX509Certificate)
                .collect(Collectors.groupingBy(X509Certificate::getSubjectX500Principal));
    }

}
