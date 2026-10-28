package com.scality.keycloak.longLivedToken;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class LongLivedTokenAdminResource {
    protected static final Logger logger = Logger.getLogger(LongLivedTokenAdminResource.class);

    private static final String OPEN_API_TAG = "Long-lived tokens";
    private static final String ADMIN_EVENT_RESOURCE = "LONG_LIVED_TOKEN";
    static final String LONG_LIVED_CLAIM = "long_lived";
    static final long MAX_LIFESPAN_SECONDS = 365L * 24 * 60 * 60;
    static final int MAX_LABEL_LENGTH = 255;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final AdminEventBuilder adminEvent;

    public LongLivedTokenAdminResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent.resource(ADMIN_EVENT_RESOURCE);
    }

    @POST
    @Path("clients/{client-uuid}")
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Issue a long-lived access token for the service account of a client. The token is returned once and never stored.")
    public LongLivedTokenResponse issueToken(@PathParam("client-uuid") String clientUuid,
            LongLivedTokenRequest request) {
        ClientModel client = realm.getClientById(clientUuid);
        if (client == null) {
            throw new NotFoundException("Client not found");
        }
        auth.clients().requireManage(client);

        if (request == null) {
            request = new LongLivedTokenRequest(null, null);
        }
        long lifespan = validateLifespan(request.lifespan());
        String label = validateLabel(request.label());
        UserModel serviceAccount = requireServiceAccount(client);

        // The context client drives the client scopes and the signature algorithm, so the token is
        // built and signed as the client's own access tokens are, not as the admin console's.
        ClientModel previousClient = session.getContext().getClient();
        session.getContext().setClient(client);
        AccessToken token;
        String encoded;
        try {
            token = createAccessToken(client, serviceAccount, lifespan);
            encoded = session.tokens().encode(token);
        } finally {
            session.getContext().setClient(previousClient);
        }

        UserModel issuer = auth.adminAuth().getUser();
        LongLivedTokenEntity entity = new LongLivedTokenEntity();
        entity.setJti(token.getId());
        entity.setRealmId(realm.getId());
        entity.setClientId(client.getId());
        entity.setLabel(label);
        entity.setIat(token.getIat());
        entity.setExp(token.getExp());
        entity.setCreatedBy(issuer.getId());
        entity.setCreatedByUsername(issuer.getUsername());
        session.getProvider(JpaConnectionProvider.class).getEntityManager().persist(entity);

        adminEvent.operation(OperationType.CREATE)
                .resourcePath(session.getContext().getUri(), token.getId())
                .representation(new LongLivedTokenResponse(null, token.getId(), token.getExp()))
                .success();
        logger.infof("Long-lived token %s issued for client %s in realm %s by %s, expires at %d",
                token.getId(), client.getClientId(), realm.getName(), issuer.getUsername(), token.getExp());

        return new LongLivedTokenResponse(encoded, token.getId(), token.getExp());
    }

    private static long validateLifespan(Long lifespan) {
        if (lifespan == null) {
            return MAX_LIFESPAN_SECONDS;
        }
        if (lifespan < 1 || lifespan > MAX_LIFESPAN_SECONDS) {
            throw new BadRequestException("Lifespan must be between 1 and " + MAX_LIFESPAN_SECONDS + " seconds");
        }
        return lifespan;
    }

    private static String validateLabel(String label) {
        if (label != null && label.length() > MAX_LABEL_LENGTH) {
            throw new BadRequestException("Label is longer than " + MAX_LABEL_LENGTH + " characters");
        }
        return label;
    }

    private UserModel requireServiceAccount(ClientModel client) {
        if (!client.isEnabled()) {
            throw new BadRequestException("Client is disabled");
        }
        if (client.isPublicClient() || client.isBearerOnly()) {
            throw new BadRequestException("Client must be confidential");
        }
        if (!client.isServiceAccountsEnabled()) {
            throw new BadRequestException("Client has no service account");
        }
        // A sender-constrained token is bound to a certificate or key at issue time. This endpoint
        // cannot bind it, so it would return a plain bearer token that bypasses the constraint.
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
        if (config.isUseMtlsHokToken() || config.isUseDPoP()) {
            throw new BadRequestException("Client requires sender-constrained tokens");
        }
        UserModel serviceAccount = session.users().getServiceAccount(client);
        if (serviceAccount == null || !serviceAccount.isEnabled()) {
            throw new BadRequestException("Client service account is missing or disabled");
        }
        return serviceAccount;
    }

    private AccessToken createAccessToken(ClientModel client, UserModel serviceAccount, long lifespan) {
        ClientConnection connection = session.getContext().getConnection();
        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session)
                .createAuthenticationSession(realm, false);
        try {
            AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
            authSession.setAuthenticatedUser(serviceAccount);
            authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                    Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

            UserSessionModel userSession = new UserSessionManager(session).createUserSession(
                    rootAuthSession.getId(), realm, serviceAccount, serviceAccount.getUsername(),
                    connection.getRemoteHost(), ServiceAccountConstants.CLIENT_AUTH, false, null, null,
                    UserSessionModel.SessionPersistenceState.TRANSIENT);
            AuthenticationManager.setClientScopesInSession(session, authSession);
            ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession,
                    authSession);
            clientSessionCtx.setAttribute(Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS);
            userSession.setNote(ServiceAccountConstants.CLIENT_ID_SESSION_NOTE, client.getClientId());
            userSession.setNote(ServiceAccountConstants.CLIENT_ID, client.getClientId());
            userSession.setNote(ServiceAccountConstants.CLIENT_HOST, connection.getRemoteHost());
            userSession.setNote(ServiceAccountConstants.CLIENT_ADDRESS, connection.getRemoteHost());

            AccessToken token = new TokenManager().createClientAccessToken(session, realm, client, serviceAccount,
                    userSession, clientSessionCtx);
            token.setSessionId(null);
            // The grant caps exp at the client and SSO session maximums, which cannot be raised
            // without changing them for the whole realm, so the requested lifespan replaces it.
            token.exp(token.getIat() + lifespan);
            token.setOtherClaims(LONG_LIVED_CLAIM, true);
            return token;
        } finally {
            session.authenticationSessions().removeRootAuthenticationSession(realm, rootAuthSession);
        }
    }
}
