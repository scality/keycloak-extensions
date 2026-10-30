package com.scality.keycloak.longLivedToken;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "LONG_LIVED_TOKEN")
public class LongLivedTokenEntity {

    @Id
    @Column(name = "JTI", nullable = false)
    private String jti;

    @Column(name = "REALM_ID", nullable = false)
    private String realmId;

    @Column(name = "CLIENT_ID", nullable = false)
    private String clientId;

    @Column(name = "LABEL")
    private String label;

    @Column(name = "IAT", nullable = false)
    private long iat;

    @Column(name = "EXP", nullable = false)
    private long exp;

    @Column(name = "REVOKED", nullable = false)
    private boolean revoked;

    @Column(name = "CREATED_BY")
    private String createdBy;

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public long getIat() {
        return iat;
    }

    public void setIat(long iat) {
        this.iat = iat;
    }

    public long getExp() {
        return exp;
    }

    public void setExp(long exp) {
        this.exp = exp;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    @Override
    public int hashCode() {
        return jti == null ? 0 : jti.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        LongLivedTokenEntity other = (LongLivedTokenEntity) obj;
        return jti == null ? other.jti == null : jti.equals(other.jti);
    }

}
