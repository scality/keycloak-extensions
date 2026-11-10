package com.scality.keycloak.longLivedToken;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;

import io.quarkus.runtime.configuration.DurationConverter;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenCategory;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.admin.OperationType;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AbstractKeycloakTransaction;
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
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class LongLivedTokenAdminResource {
    protected static final Logger logger = Logger.getLogger(LongLivedTokenAdminResource.class);

    private static final String OPEN_API_TAG = "Long-lived tokens";
    private static final String ADMIN_EVENT_RESOURCE = "LONG_LIVED_TOKEN";
    static final String LONG_LIVED_CLAIM = "long_lived";
    static final Duration MIN_LIFESPAN = Duration.ofSeconds(1);
    static final Duration MAX_LIFESPAN = Duration.ofDays(365);
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
        Duration lifespan = validateLifespan(request.lifespan());
        String label = validateLabel(request.label());
        UserModel serviceAccount = requireServiceAccount(client);

        // The context client drives the client scopes and the signature algorithm, so the token is
        // built and signed as the client's own access tokens are, not as the admin console's.
        ClientModel previousClient = session.getContext().getClient();
        session.getContext().setClient(client);
        AccessToken token;
        String algorithm;
        KeyPair keyPair;
        String encoded;
        try {
            algorithm = session.tokens().signatureAlgorithm(TokenCategory.ACCESS);
            if (!LongLivedTokenSigningKeys.isSupported(algorithm)) {
                throw new BadRequestException("Client signs access tokens with " + algorithm
                        + ", which long-lived tokens do not support: their keys are published, so they need an"
                        + " RS*, PS* or ES* algorithm");
            }
            token = createAccessToken(client, serviceAccount, lifespan);
            keyPair = LongLivedTokenSigningKeys.generate(algorithm);
            encoded = sign(token, client, LongLivedTokenSigningKeys.signingKey(token.getId(), algorithm, keyPair));
        } finally {
            session.getContext().setClient(previousClient);
        }
        LongLivedTokenKeyProviderFactory.ensureComponent(realm);

        UserModel issuer = auth.adminAuth().getUser();
        LongLivedTokenEntity entity = new LongLivedTokenEntity();
        entity.setJti(token.getId());
        entity.setRealmId(realm.getId());
        entity.setClientId(client.getId());
        entity.setLabel(label);
        entity.setIat(token.getIat());
        entity.setExp(token.getExp());
        entity.setCreatedBy(issuer.getId());
        entity.setAlgorithm(algorithm);
        entity.setPublicKey(LongLivedTokenSigningKeys.encode(keyPair.getPublic()));
        getEntityManager().persist(entity);

        adminEvent.operation(OperationType.CREATE)
                .resourcePath(session.getContext().getUri(), token.getId())
                .representation(new LongLivedTokenResponse(null, token.getId(), token.getExp()))
                .success();
        logOnCommit(String.format("Long-lived token %s issued for client %s in realm %s by user %s, expires at %d",
                token.getId(), client.getClientId(), realm.getName(), issuer.getId(), token.getExp()));

        return new LongLivedTokenResponse(encoded, token.getId(), token.getExp());
    }

    @GET
    @Path("clients/{client-uuid}")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "List the long-lived tokens issued for a client, newest first, without the tokens themselves.")
    public List<LongLivedTokenInfo> listTokens(@PathParam("client-uuid") String clientUuid) {
        ClientModel client = realm.getClientById(clientUuid);
        if (client == null) {
            throw new NotFoundException("Client not found");
        }
        auth.clients().requireView(client);

        return getEntityManager()
                .createQuery("SELECT t FROM LongLivedTokenEntity t WHERE t.realmId = :realmId"
                        + " AND t.clientId = :clientId ORDER BY t.iat DESC", LongLivedTokenEntity.class)
                .setParameter("realmId", realm.getId())
                .setParameter("clientId", client.getId())
                .getResultStream()
                .map(LongLivedTokenInfo::of)
                .toList();
    }

    @POST
    @Path("{jti}/revoke")
    @NoCache
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Revoke a long-lived token. Its key leaves the realm JWKS, so the realm no longer accepts it.")
    public void revokeToken(@PathParam("jti") String jti) {
        LongLivedTokenEntity entity = findToken(jti);
        ClientModel client = realm.getClientById(entity.getClientId());
        auth.clients().requireManage(client);

        if (entity.isRevoked()) {
            return;
        }
        entity.setRevoked(true);

        adminEvent.operation(OperationType.ACTION)
                .resourcePath(session.getContext().getUri())
                .success();
        logOnCommit(String.format("Long-lived token %s of client %s in realm %s revoked by user %s",
                jti, client.getClientId(), realm.getName(), auth.adminAuth().getUser().getId()));
    }

    @DELETE
    @Path("{jti}")
    @NoCache
    @Tag(name = OPEN_API_TAG)
    @Operation(summary = "Delete an expired long-lived token from the registry. A token that has not expired yet must be revoked instead.")
    public void deleteToken(@PathParam("jti") String jti) {
        LongLivedTokenEntity entity = findToken(jti);
        ClientModel client = realm.getClientById(entity.getClientId());
        auth.clients().requireManage(client);

        // The token check rejects tokens missing from the registry, so deleting a live token would
        // revoke it and hide it from the list.
        if (entity.getExp() > Time.currentTime()) {
            throw new ClientErrorException("Only an expired long-lived token can be deleted; revoke it instead",
                    Response.Status.CONFLICT);
        }
        getEntityManager().remove(entity);

        adminEvent.operation(OperationType.DELETE)
                .resourcePath(session.getContext().getUri())
                .success();
        logOnCommit(String.format("Expired long-lived token %s of client %s in realm %s deleted by user %s",
                jti, client.getClientId(), realm.getName(), auth.adminAuth().getUser().getId()));
    }

    // A registry row is deleted with its client (foreign key ON DELETE CASCADE), so the client
    // of a token found here always exists.
    private LongLivedTokenEntity findToken(String jti) {
        LongLivedTokenEntity entity = getEntityManager().find(LongLivedTokenEntity.class, jti);
        if (entity == null || !entity.getRealmId().equals(realm.getId())) {
            throw new NotFoundException("Long-lived token not found");
        }
        return entity;
    }

    private EntityManager getEntityManager() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    // Logged only on commit: a failed admin event write rolls the change back, so an inline log
    // would report a change that never happened.
    private void logOnCommit(String message) {
        session.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction() {
            @Override
            protected void commitImpl() {
                logger.info(message);
            }

            @Override
            protected void rollbackImpl() {
            }
        });
    }

    private String sign(AccessToken token, ClientModel client, KeyWrapper key) {
        String type = OIDCAdvancedConfigWrapper.fromClientModel(client).isUseRfc9068AccessTokenHeaderType()
                ? "at+jwt" : "JWT";
        try {
            SignatureSignerContext signer = session.getProvider(SignatureProvider.class, key.getAlgorithm())
                    .signer(key);
            return new JWSBuilder().type(type).jsonContent(token).sign(signer);
        } catch (SignatureException e) {
            throw new IllegalStateException("Cannot sign long-lived token " + token.getId(), e);
        }
    }

    // Jackson coerces a JSON number into this String field and DurationConverter reads a bare
    // number as seconds, so clients still sending the lifespan as a number keep working.
    private static Duration validateLifespan(String lifespan) {
        if (lifespan == null) {
            return MAX_LIFESPAN;
        }
        String error = "Lifespan must be a whole number of seconds between " + MIN_LIFESPAN.toSeconds() + "s and "
                + MAX_LIFESPAN.toDays() + "d, as seconds or a duration such as 48h or 30d";
        Duration duration;
        try {
            duration = DurationConverter.parseDuration(lifespan);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(error);
        }
        if (duration == null || duration.getNano() != 0 || duration.compareTo(MIN_LIFESPAN) < 0
                || duration.compareTo(MAX_LIFESPAN) > 0) {
            throw new BadRequestException(error);
        }
        return duration;
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

    private AccessToken createAccessToken(ClientModel client, UserModel serviceAccount, Duration lifespan) {
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
                    userSession, clientSessionCtx, clientSessionCtx.isOfflineTokenRequested());
            token.setSessionId(null);
            // The grant caps exp at the client and SSO session maximums, which cannot be raised
            // without changing them for the whole realm, so the requested lifespan replaces it.
            token.exp(token.getIat() + lifespan.toSeconds());
            token.setOtherClaims(LONG_LIVED_CLAIM, true);
            return token;
        } finally {
            session.authenticationSessions().removeRootAuthenticationSession(realm, rootAuthSession);
        }
    }
}
