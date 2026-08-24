package com.scality.keycloak.authentication;

import javax.naming.NamingException;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * Username/password form authenticator that degrades gracefully when the LDAP directory is
 * unreachable (RING-54200).
 *
 * <p>Stock {@link UsernamePasswordForm} lets the LDAP-connectivity failure (a
 * {@link org.keycloak.models.ModelException} whose cause chain reaches {@link NamingException})
 * propagate out of the login flow, where it surfaces as a raw HTTP 500 — or, if the socket hangs
 * past the reverse proxy's read timeout, an Apache "502 Proxy Error". Both leak a distinct
 * "backend down" state and confuse the user.
 *
 * <p>This authenticator catches that failure and re-renders the login page with a dedicated,
 * honest message ("temporarily unavailable, try again later") instead of the misleading
 * "Invalid username or password". Because the connectivity error is caught at the flow level
 * (the stock provider still <em>throws</em> rather than returning {@code null}), imported users
 * are never purged. Any non-connectivity error is rethrown unchanged.
 */
public class LdapAwareUsernamePasswordForm extends UsernamePasswordForm {

    private static final Logger log = Logger.getLogger(LdapAwareUsernamePasswordForm.class);

    /** Message key from theme-resources/messages/messages_*.properties bundled in this jar. */
    static final String LDAP_UNAVAILABLE_MESSAGE = "ldapUnavailableError";

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        try {
            return super.validateForm(context, formData);
        } catch (RuntimeException e) {
            if (isLdapConnectivityError(e)) {
                log.warnf(e, "LDAP unreachable during login; rendering the service-unavailable message");
                Response challenge = context.form()
                        .setError(LDAP_UNAVAILABLE_MESSAGE)
                        .createLoginUsernamePassword();
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                return false;
            }
            throw e;
        }
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
}
