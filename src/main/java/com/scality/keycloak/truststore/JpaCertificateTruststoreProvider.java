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
import org.hibernate.exception.GenericJDBCException;
import org.hibernate.jpa.AvailableHints;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Retry;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ErrorResponse;

import jakarta.persistence.EntityManager;
import jakarta.persistence.FlushModeType;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response.Status;
import java.sql.SQLException;

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

    /**
     * Checks if the exception is related to a closed connection or statement.
     * These errors can occur when the connection pool closes connections due to timeouts
     * or when transactions are committed/rolled back prematurely.
     */
    private boolean isConnectionClosedError(Throwable e) {
        if (e == null) {
            return false;
        }
        
        String message = e.getMessage();
        if (message != null) {
            String lowerMessage = message.toLowerCase();
            if (lowerMessage.contains("connection is closed") ||
                lowerMessage.contains("this statement has been closed") ||
                lowerMessage.contains("statement has been closed") ||
                lowerMessage.contains("connection closed")) {
                return true;
            }
        }
        
        // Check for SQLException with specific SQL states
        if (e instanceof SQLException) {
            SQLException sqlEx = (SQLException) e;
            String sqlState = sqlEx.getSQLState();
            // SQLState 55000 is a generic PostgreSQL error that can indicate connection issues
            if ("55000".equals(sqlState) || sqlState == null) {
                return true;
            }
        }
        
        // Check for GenericJDBCException which wraps SQL exceptions
        if (e instanceof GenericJDBCException) {
            return isConnectionClosedError(e.getCause());
        }
        
        // Recursively check cause
        return isConnectionClosedError(e.getCause());
    }

    /**
     * Checks if the exception is related to a Hibernate flush error.
     * This can occur when Hibernate tries to flush pending changes during cascade operations.
     */
    private boolean isHibernateFlushError(Throwable e) {
        if (e == null) {
            return false;
        }
        
        // Check for HibernateException with flush-related messages
        if (e instanceof org.hibernate.HibernateException) {
            String message = e.getMessage();
            if (message != null) {
                String lowerMessage = message.toLowerCase();
                if (lowerMessage.contains("flush during cascade") ||
                    lowerMessage.contains("flush is dangerous")) {
                    return true;
                }
            }
        }
        
        // Recursively check cause
        return isHibernateFlushError(e.getCause());
    }

    @Override
    public void close() {
        // nothing to close
    }

    private CertificateRepresentation toCertificateRepresentation(TruststoreEntity entity) {
        X509Certificate x509Certificate = toX509Certificate(entity.getCertificate());
        try {
            X500Name x500name = new JcaX509CertificateHolder(x509Certificate).getSubject();
            RDN[] rdns = x500name.getRDNs(BCStyle.CN);
            RDN cn = rdns.length > 0 ? rdns[0] : null;

            CertificateRepresentation certificate = new CertificateRepresentation(
                    entity.getAlias(),
                    entity.getCertificate(),
                    cn != null ? IETFUtils.valueToString(cn.getFirst().getValue()) : "-");

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
        // First attempt: Check if certificate exists (throws NotFoundException immediately if not found)
        // This prevents retrying "not found" conditions which are permanent, not transient errors
        try {
            TruststoreEntity certificate = getEntityManager()
                    .createNamedQuery("findByAlias", TruststoreEntity.class)
                    .setParameter("alias", alias)
                    .getSingleResult();
            return toCertificateRepresentation(certificate);
        } catch (NoResultException e) {
            throw new NotFoundException("Certificate not found");
        } catch (RuntimeException e) {
            // If it's a connection closed error, retry the operation
            // NotFoundException and other non-connection errors are rethrown immediately
            if (isConnectionClosedError(e)) {
                try {
                    return Retry.call((iteration) -> {
                        try {
                            TruststoreEntity certificate = getEntityManager()
                                    .createNamedQuery("findByAlias", TruststoreEntity.class)
                                    .setParameter("alias", alias)
                                    .getSingleResult();
                            return toCertificateRepresentation(certificate);
                        } catch (NoResultException ne) {
                            throw new NotFoundException("Certificate not found");
                        } catch (RuntimeException re) {
                            // Only retry on connection closed errors
                            if (isConnectionClosedError(re) && iteration < 2) {
                                logger.debugf("Connection closed error on getCertificate, retrying (iteration %d)", iteration);
                                getEntityManager().clear();
                                throw re;
                            }
                            throw re;
                        }
                    }, 3, 50); // 3 attempts with 50ms delay
                } catch (NotFoundException nfe) {
                    throw nfe;
                } catch (Exception retryEx) {
                    if (retryEx.getCause() instanceof NotFoundException) {
                        throw (NotFoundException) retryEx.getCause();
                    }
                    throw new RuntimeException("Failed to get certificate: " + alias, retryEx);
                }
            }
            // For other runtime exceptions, rethrow them
            throw e;
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
        try {
            return Retry.call((iteration) -> {
                try {
                    EntityManager em = getEntityManager();
                    // Set flush mode to COMMIT to prevent automatic flushing before query execution
                    // This prevents "Flush during cascade is dangerous" errors when there are
                    // pending changes in the session from other operations
                    FlushModeType originalFlushMode = em.getFlushMode();
                    try {
                        em.setFlushMode(FlushModeType.COMMIT);
                        @SuppressWarnings("unchecked")
                        List<TruststoreEntity> list = (List<TruststoreEntity>) em
                                .createNativeQuery("select t.id, t.alias, t.certificate, t.is_root_ca from truststore t",
                                        TruststoreEntity.class)
                                .setHint(AvailableHints.HINT_CACHEABLE, false)
                                .setHint(AvailableHints.HINT_CACHE_MODE, CacheMode.IGNORE)
                                .getResultList();
                        return list.stream()
                                .map(this::toCertificateRepresentation)
                                .toArray(CertificateRepresentation[]::new);
                    } finally {
                        // Restore original flush mode
                        em.setFlushMode(originalFlushMode);
                    }
                } catch (RuntimeException e) {
                    // Only retry on connection closed errors or Hibernate flush errors
                    if ((isConnectionClosedError(e) || isHibernateFlushError(e)) && iteration < 2) {
                        logger.debugf("Connection or flush error on getCertificates, retrying (iteration %d)", iteration);
                        // Clear the entity manager to force a new connection on retry
                        getEntityManager().clear();
                        throw e;
                    }
                    throw e;
                }
            }, 3, 50); // 3 attempts with 50ms delay
        } catch (Exception e) {
            logger.error("Failed to get certificates after retries", e);
            throw new RuntimeException("Failed to get certificates", e);
        }
    }

    @Override
    public CertificateRepresentation[] getCertificates(boolean isRootCA) {
        try {
            return Retry.call((iteration) -> {
                try {
                    EntityManager em = getEntityManager();
                    // Set flush mode to COMMIT to prevent automatic flushing before query execution
                    // This prevents "Flush during cascade is dangerous" errors when there are
                    // pending changes in the session from other operations
                    FlushModeType originalFlushMode = em.getFlushMode();
                    try {
                        em.setFlushMode(FlushModeType.COMMIT);
                        return em
                                .createNamedQuery("findByIsRootCA", TruststoreEntity.class)
                                .setParameter("isRootCA", isRootCA)
                                .getResultList()
                                .stream()
                                .map(this::toCertificateRepresentation)
                                .toArray(CertificateRepresentation[]::new);
                    } finally {
                        // Restore original flush mode
                        em.setFlushMode(originalFlushMode);
                    }
                } catch (RuntimeException e) {
                    // Only retry on connection closed errors or Hibernate flush errors
                    if ((isConnectionClosedError(e) || isHibernateFlushError(e)) && iteration < 2) {
                        logger.debugf("Connection or flush error on getCertificates(isRootCA=%s), retrying (iteration %d)", isRootCA, iteration);
                        // Clear the entity manager to force a new connection on retry
                        getEntityManager().clear();
                        throw e;
                    }
                    throw e;
                }
            }, 3, 50); // 3 attempts with 50ms delay
        } catch (Exception e) {
            logger.errorf("Failed to get certificates (isRootCA=%s) after retries", isRootCA, e);
            throw new RuntimeException("Failed to get certificates", e);
        }
    }

    @Override
    public X509Certificate toX509Certificate(CertificateRepresentation certificate) {
        return toX509Certificate(certificate.certificate());
    }

}
