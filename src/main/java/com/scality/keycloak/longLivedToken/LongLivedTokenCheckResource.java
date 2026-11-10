package com.scality.keycloak.longLivedToken;

import java.util.List;
import java.util.regex.Pattern;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.TokenUtil;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class LongLivedTokenCheckResource {

    private static final String BEARER = "Bearer";
    private static final String BASIC = "Basic";
    private static final Pattern COMPACT_JWS = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    private final KeycloakSession session;

    public LongLivedTokenCheckResource(KeycloakSession session) {
        this.session = session;
    }

    // Envoy's HTTP ext_authz keeps the method of the request it guards; ingress-nginx sends a GET.
    @GET
    @Path("check")
    public Response checkGet() {
        return check();
    }

    @HEAD
    @Path("check")
    public Response checkHead() {
        return check();
    }

    @POST
    @Path("check")
    public Response checkPost() {
        return check();
    }

    @PUT
    @Path("check")
    public Response checkPut() {
        return check();
    }

    @PATCH
    @Path("check")
    public Response checkPatch() {
        return check();
    }

    @DELETE
    @Path("check")
    public Response checkDelete() {
        return check();
    }

    @OPTIONS
    @Path("check")
    public Response checkOptions() {
        return check();
    }

    private Response check() {
        List<String> authorizations = session.getContext().getRequestHeaders().getRequestHeader(HttpHeaders.AUTHORIZATION);
        if (authorizations == null || authorizations.isEmpty()) {
            return allowed();
        }
        // The proxy forwards every header and its upstream may read only the first one, so any
        // value this check would read differently is refused rather than passed on unchecked.
        if (authorizations.size() > 1) {
            return refused();
        }
        String authorization = authorizations.get(0);
        int separator = firstWhitespace(authorization);
        String scheme = separator < 0 ? authorization : authorization.substring(0, separator);
        // The proxy would also take a JWT from either part of Basic credentials, so Basic is
        // refused instead of decoded.
        if (scheme.equalsIgnoreCase(BASIC)) {
            return refused();
        }
        if (!scheme.equalsIgnoreCase(BEARER)) {
            return allowed();
        }
        if (separator < 0 || authorization.charAt(separator) != ' ') {
            return refused();
        }
        String value = authorization.substring(separator + 1);
        if (!COMPACT_JWS.matcher(value).matches()) {
            return refused();
        }
        AccessToken token = session.tokens().decode(value, AccessToken.class);
        if (token == null) {
            // A revoked token's key has left the realm JWKS, so the realm can no longer verify it,
            // but a proxy that cached the JWKS still can. Read unverified, a token claiming to be
            // long-lived is refused.
            return isLongLived(readUnverified(value)) ? refused() : allowed();
        }
        if (!isLongLived(token)) {
            return allowed();
        }
        return isValidLongLivedToken(token) ? allowed() : refused();
    }

    // The checks the userinfo endpoint runs, minus the user session a long-lived token never has and
    // the issuer, which follows the host the proxy calls: the token's own key already ties it to the
    // realm. The client comes from the registry, so renaming it keeps its tokens valid.
    private boolean isValidLongLivedToken(AccessToken token) {
        RealmModel realm = session.getContext().getRealm();
        LongLivedTokenEntity entity = session.getProvider(JpaConnectionProvider.class).getEntityManager()
                .find(LongLivedTokenEntity.class, token.getId());
        if (entity == null || !entity.getRealmId().equals(realm.getId()) || entity.isRevoked()) {
            return false;
        }
        ClientModel client = realm.getClientById(entity.getClientId());
        if (client == null || !client.isEnabled()) {
            return false;
        }
        try {
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(TokenVerifier.IS_ACTIVE, new TokenVerifier.TokenTypeCheck(List.of(TokenUtil.TOKEN_TYPE_BEARER)),
                            TokenManager.NotBeforeCheck.forModel(realm), TokenManager.NotBeforeCheck.forModel(client),
                            new TokenManager.TokenRevocationCheck(session))
                    .verify();
        } catch (VerificationException e) {
            return false;
        }
        UserModel user = token.getSubject() == null ? null : session.users().getUserById(realm, token.getSubject());
        return user != null && user.isEnabled() && client.getId().equals(user.getServiceAccountClientLink())
                && TokenManager.validateUserNotBefore(session, realm, token, user);
    }

    private static boolean isLongLived(AccessToken token) {
        return token != null
                && Boolean.TRUE.equals(token.getOtherClaims().get(LongLivedTokenAdminResource.LONG_LIVED_CLAIM));
    }

    private static AccessToken readUnverified(String encodedToken) {
        try {
            return new JWSInput(encodedToken).readJsonContent(AccessToken.class);
        } catch (JWSInputException | RuntimeException e) {
            return null;
        }
    }

    private static int firstWhitespace(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isWhitespace(value.charAt(i))) {
                return i;
            }
        }
        return -1;
    }

    // Keycloak answers 500 to a response that has no media type.
    private static Response allowed() {
        return Response.ok().type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    private static Response refused() {
        return Response.status(Response.Status.UNAUTHORIZED).type(MediaType.TEXT_PLAIN_TYPE).build();
    }

}
