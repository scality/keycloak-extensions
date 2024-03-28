package com.scality.keycloak.groupFederationLink;

import org.keycloak.models.jpa.entities.GroupEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "GROUP_FEDERATION_LINK", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "GROUP_ID" })
})
@NamedQueries({
        @NamedQuery(name = "findByFederationLink", query = "select t from GroupFederationLinkEntity t where t.federationLink = :federationLink"),
        @NamedQuery(name = "findByGroupId", query = "select t from GroupFederationLinkEntity t where t.groupId = :groupId"),
        @NamedQuery(name = "findGroupsByFederationLinkAndName", query = "select g from GroupFederationLinkEntity gl, GroupEntity g where gl.groupId = g.id and g.name like concat('%',:name,'%') and gl.federationLink = :federationLink"),
        @NamedQuery(name = "findGroupsByFederationLink", query = "select g from GroupFederationLinkEntity gl, GroupEntity g where gl.groupId = g.id and gl.federationLink = :federationLink"),
})
public class GroupFederationLinkEntity {

    @Id
    @Column(name = "GROUP_ID", nullable = false)
    private String groupId;

    @Column(name = "FEDERATION_LINK", nullable = false)
    private String federationLink;

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public String getFederationLink() {
        return federationLink;
    }

    public void setFederationLink(String federationLink) {
        this.federationLink = federationLink;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((groupId == null) ? 0 : groupId.hashCode());
        result = prime * result + ((federationLink == null) ? 0 : federationLink.hashCode());
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
        GroupFederationLinkEntity other = (GroupFederationLinkEntity) obj;
        if (groupId == null) {
            if (other.groupId != null)
                return false;
        } else if (!groupId.equals(other.groupId))
            return false;
        if (federationLink == null) {
            if (other.federationLink != null)
                return false;
        } else if (!federationLink.equals(other.federationLink))
            return false;
        return true;
    }

}
