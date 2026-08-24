package com.scality.keycloak.authentication;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory for {@link LdapAwareUsernamePasswordForm}. Registered via
 * META-INF/services/org.keycloak.authentication.AuthenticatorFactory.
 *
 * <p>The provider id is kept &le; 36 characters so it fits Keycloak's
 * {@code AUTHENTICATION_EXECUTION.AUTHENTICATOR varchar(36)} column — otherwise the authenticator
 * cannot be bound into any flow.
 */
public class LdapAwareUsernamePasswordFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "ldap-aware-username-password"; // 28 chars

    public static final LdapAwareUsernamePasswordForm SINGLETON = new LdapAwareUsernamePasswordForm();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Username Password Form (LDAP-outage aware)";
    }

    @Override
    public String getHelpText() {
        return "Username/password form that shows a generic 'service temporarily unavailable' message "
                + "when the LDAP directory is unreachable, instead of a raw 500/502.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
}
