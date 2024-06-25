package com.scality.keycloak.truststore;

import jakarta.persistence.Cacheable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "TRUSTSTORE", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "ID", "ALIAS" })
})
@Cacheable(false)
@NamedQueries({
        @NamedQuery(name = "findAll", query = "select t from TruststoreEntity t"),
        @NamedQuery(name = "findByAlias", query = "select t from TruststoreEntity t where t.alias = :alias"),
        @NamedQuery(name = "findByIsRootCA", query = "select t from TruststoreEntity t where t.isRootCA = :isRootCA"),
})
public class TruststoreEntity {

    @Id
    @Column(name = "ID", nullable = false)
    private String id;

    @Column(name = "ALIAS", nullable = false)
    private String alias;

    // Base64 encoded certificate
    @Column(name = "CERTIFICATE", nullable = false)
    private String certificate;

    @Column(name = "IS_ROOT_CA", nullable = false)
    private boolean isRootCA;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public boolean isRootCA() {
        return isRootCA;
    }

    public void setRootCA(boolean isRootCA) {
        this.isRootCA = isRootCA;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((alias == null) ? 0 : alias.hashCode());
        result = prime * result + ((certificate == null) ? 0 : certificate.hashCode());
        result = prime * result + (isRootCA ? 1231 : 1237);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        TruststoreEntity other = (TruststoreEntity) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (alias == null) {
            if (other.alias != null)
                return false;
        } else if (!alias.equals(other.alias))
            return false;
        if (certificate == null) {
            if (other.certificate != null)
                return false;
        } else if (!certificate.equals(other.certificate))
            return false;
        if (isRootCA != other.isRootCA)
            return false;
        return true;
    }
}
