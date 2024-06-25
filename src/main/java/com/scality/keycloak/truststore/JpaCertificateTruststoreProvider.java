package com.scality.keycloak.truststore;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.hibernate.CacheMode;
import org.hibernate.jpa.AvailableHints;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ErrorResponse;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response.Status;

public class JpaCertificateTruststoreProvider implements CertificateTruststoreProvider {

    private final KeycloakSession session;
    protected static final Logger logger = Logger.getLogger(JpaCertificateTruststoreProvider.class);

    public JpaCertificateTruststoreProvider(KeycloakSession session) {
        this.session = session;
    }

    /***
     * 
     * @return EntityManager
     */
    private EntityManager getEntityManager() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    @Override
    public void close() {
        // nothing to close
    }

    private CertificateRepresentation toCertificateRepresentation(TruststoreEntity entity) {
        X509Certificate x509Certificate = toX509Certificate(entity.getCertificate());
        try {
            X500Name x500name = new JcaX509CertificateHolder(x509Certificate).getSubject();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];

            CertificateRepresentation certificate = new CertificateRepresentation(
                    entity.getAlias(),
                    entity.getCertificate(),
                    IETFUtils.valueToString(cn.getFirst().getValue()));

            return certificate;

        } catch (CertificateEncodingException e) {
            logger.error("certificate " + entity.getAlias() + " is invalid", e);
            CertificateRepresentation certificate = new CertificateRepresentation(
                    entity.getAlias(),
                    entity.getCertificate(),
                    "");
            return certificate;
        }

    }

    @Override
    public CertificateRepresentation getCertificate(String alias) {
        try {
            TruststoreEntity certificate = getEntityManager()
                    .createNamedQuery("findByAlias", TruststoreEntity.class)
                    .setParameter("alias", alias)
                    .getSingleResult();
            return toCertificateRepresentation(certificate);
        } catch (NoResultException e) {
            throw new NotFoundException("Certificate not found");
        }
    }

    /**
     * Checks whether given X.509 certificate is self-signed.
     */
    private boolean isSelfSigned(X509Certificate cert) {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            logger.trace("certificate " + cert.getSubjectX500Principal().getName() + " detected as root CA");
            return true;
        } catch (SignatureException sigEx) {
            // Invalid signature --> not self-signed
            logger.trace("certificate " + cert.getSubjectX500Principal().getName() + " detected as intermediate CA");
        } catch (InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
            logger.trace("certificate " + cert.getSubjectX500Principal().getName() + " detected as intermediate CA");
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            logger.error("certificate " + cert.getSubjectX500Principal().getName() + " is invalid", e);
            throw ErrorResponse.error("Certificate is invalid", Status.BAD_REQUEST);
        }
        return false;
    }

    private X509Certificate toX509Certificate(String certificate) {
        String pemEncoded = new String(Base64.getDecoder().decode(certificate));
        // Remove PEM header and footer
        String pemContent = pemEncoded
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "").replaceAll("\\n", "");

        // Decode Base64
        byte[] decodedBytes = Base64.getDecoder().decode(pemContent);

        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(decodedBytes));
        } catch (CertificateException e) {
            logger.error("certificate " + certificate + " is invalid", e);
            throw ErrorResponse.error("Certificate is invalid", Status.BAD_REQUEST);
        }
    }

    @Override
    public CertificateRepresentation addCertificate(String alias, String certificate) {
        X509Certificate x509Certificate = toX509Certificate(certificate);

        final String id = KeycloakModelUtils.generateId();
        TruststoreEntity entity = new TruststoreEntity();
        entity.setId(id);
        entity.setAlias(alias);
        entity.setCertificate(certificate);
        entity.setRootCA(isSelfSigned(x509Certificate));
        getEntityManager().persist(entity);
        getEntityManager().flush();
        getEntityManager().clear();

        return toCertificateRepresentation(entity);
    }

    @Override
    public CertificateRepresentation updateCertificate(String alias, String certificate) {
        TruststoreEntity storedCertificate = getEntityManager()
                .createNamedQuery("findByAlias", TruststoreEntity.class)
                .setParameter("alias", alias)
                .getSingleResult();
        X509Certificate x509Certificate = toX509Certificate(storedCertificate.getCertificate());

        TruststoreEntity entity = new TruststoreEntity();
        entity.setId(storedCertificate.getId());
        entity.setAlias(alias);
        entity.setCertificate(certificate);
        entity.setRootCA(isSelfSigned(x509Certificate));
        getEntityManager().merge(entity);
        getEntityManager().flush();
        getEntityManager().clear();

        return toCertificateRepresentation(entity);
    }

    @Override
    public void removeCertificate(String alias) {
        TruststoreEntity entity = getEntityManager()
                .createNamedQuery("findByAlias", TruststoreEntity.class)
                .setParameter("alias", alias)
                .getSingleResult();
        getEntityManager().remove(entity);
        getEntityManager().flush();
        getEntityManager().clear();
    }

    @Override
    public CertificateRepresentation[] getCertificates() {
        getEntityManager().clear();
        List<TruststoreEntity> list = (List<TruststoreEntity>) getEntityManager()
                .createNativeQuery("select t.id, t.alias, t.certificate, t.is_root_ca from truststore t",
                        TruststoreEntity.class)
                .setHint(AvailableHints.HINT_CACHEABLE, false)
                .setHint(AvailableHints.HINT_CACHE_MODE, CacheMode.IGNORE)
                .getResultList();
        return list.stream()
                .map(this::toCertificateRepresentation)
                .toArray(CertificateRepresentation[]::new);
    }

    @Override
    public CertificateRepresentation[] getCertificates(boolean isRootCA) {
        return getEntityManager()
                .createNamedQuery("findByIsRootCA", TruststoreEntity.class)
                .setParameter("isRootCA", isRootCA)
                .getResultList()
                .stream()
                .map(this::toCertificateRepresentation)
                .toArray(CertificateRepresentation[]::new);
    }

    @Override
    public X509Certificate toX509Certificate(CertificateRepresentation certificate) {
        return toX509Certificate(certificate.certificate());
    }

}
