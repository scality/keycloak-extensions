package com.scality.keycloak.ldapWithoutMappers;

import javax.naming.NamingException;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;

/**
 * LDAP storage provider that stays graceful when the LDAP server is unreachable.
 *
 * <p>Stock {@link LDAPStorageProvider} throws a {@link org.keycloak.models.ModelException}
 * (wrapping a {@link NamingException}) on any connectivity failure during the login flow's
 * user lookup / credential validation. Uncaught, that surfaces to the browser as a raw HTTP 500
 * (or, if the socket hangs past the reverse proxy's read timeout, an Apache "502 Proxy Error"),
 * leaking a distinct "backend unavailable" state instead of the generic login error OWASP
 * requires (RING-54200).
 *
 * <p>This subclass intercepts LDAP-connectivity failures on the authentication code paths and
 * converts them into Keycloak's normal "user not found" / "invalid credentials" outcome, so the
 * user sees the same generic message used for a wrong password. Non-connectivity errors are
 * rethrown unchanged.
 *
 * <p>Safety for imported users: on a connectivity error inside {@link #validate} we return the
 * existing imported user unchanged rather than {@code null}. Returning {@code null} would make
 * {@code UserStorageManager.importValidation} treat the user as removed from LDAP and delete the
 * local copy (Keycloak's {@code removeInvalidUsers} defaults to {@code true}); an outage must not
 * purge every imported user. Genuine "user absent while LDAP is reachable" still returns
 * {@code null} (correct removal).
 */
public class ResilientLDAPStorageProvider extends LDAPStorageProvider {

    private static final Logger log = Logger.getLogger(ResilientLDAPStorageProvider.class);

    public ResilientLDAPStorageProvider(LDAPStorageProviderFactory factory, KeycloakSession session,
            ComponentModel model, LDAPIdentityStore ldapIdentityStore) {
        super(factory, session, model, ldapIdentityStore);
    }

    /** True if the throwable chain contains a {@link NamingException} (Communication/ServiceUnavailable are subclasses). */
    private static boolean isLdapConnectivityError(Throwable t) {
        for (Throwable cause = t; cause != null; cause = cause.getCause()) {
            if (cause instanceof NamingException) {
                return true;
            }
        }
        return false;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        try {
            return super.getUserByUsername(realm, username);
        } catch (RuntimeException e) {
            if (isLdapConnectivityError(e)) {
                log.warnf(e, "LDAP unreachable during getUserByUsername('%s'); treating as user not found", username);
                return null;
            }
            throw e;
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        try {
            return super.getUserByEmail(realm, email);
        } catch (RuntimeException e) {
            if (isLdapConnectivityError(e)) {
                log.warnf(e, "LDAP unreachable during getUserByEmail; treating as user not found");
                return null;
            }
            throw e;
        }
    }

    @Override
    public UserModel validate(RealmModel realm, UserModel local) {
        try {
            return super.validate(realm, local);
        } catch (RuntimeException e) {
            if (isLdapConnectivityError(e)) {
                // Return the existing user (never null) so the imported local copy is not purged.
                log.warnf(e, "LDAP unreachable during validate('%s'); keeping imported user", local.getUsername());
                return local;
            }
            throw e;
        }
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        try {
            return super.isValid(realm, user, input);
        } catch (RuntimeException e) {
            if (isLdapConnectivityError(e)) {
                log.warnf(e, "LDAP unreachable during credential validation for '%s'; treating as invalid", user.getUsername());
                return false;
            }
            throw e;
        }
    }
}
