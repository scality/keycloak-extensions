package com.scality.keycloak.authentication;

import javax.naming.NamingException;

import jakarta.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.ModelException;
import org.keycloak.services.messages.Messages;

public class LdapResilientUsernamePasswordForm extends UsernamePasswordForm {

    private static final Logger LOGGER = Logger.getLogger(LdapResilientUsernamePasswordForm.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            super.authenticate(context);
        } catch (ModelException e) {
            handleLdapUnreachable(context, e);
        }
    }

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        try {
            return super.validateForm(context, formData);
        } catch (ModelException e) {
            handleLdapUnreachable(context, e);
            return false;
        }
    }

    private void handleLdapUnreachable(AuthenticationFlowContext context, ModelException e) {
        NamingException namingException = findNamingException(e);
        if (namingException == null) {
            throw e;
        }

        LOGGER.warnv(namingException, "LDAP server unreachable during authentication: {0}",
                namingException.getMessage());

        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                challenge(context, Messages.INVALID_USER));
    }

    private static NamingException findNamingException(Throwable throwable) {
        Throwable cause = throwable;
        while (cause != null) {
            if (cause instanceof NamingException) {
                return (NamingException) cause;
            }
            cause = cause.getCause();
        }
        return null;
    }
}
