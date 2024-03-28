package com.scality.keycloak.groupFederationLink;

import org.keycloak.representations.idm.GroupRepresentation;

public class GroupWithLinkRepresentation extends GroupRepresentation {
    protected String federationLink;

    public String getFederationLink() {
        return federationLink;
    }

    public void setFederationLink(String federationLink) {
        this.federationLink = federationLink;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((federationLink == null) ? 0 : federationLink.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        GroupWithLinkRepresentation other = (GroupWithLinkRepresentation) obj;
        if (federationLink == null) {
            if (other.federationLink != null)
                return false;
        } else if (!federationLink.equals(other.federationLink))
            return false;
        return true;
    }

}
