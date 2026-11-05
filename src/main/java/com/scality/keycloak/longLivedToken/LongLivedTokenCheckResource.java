package com.scality.keycloak.longLivedToken;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;

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

    // An authorization subrequest keeps the method of the request it guards.
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
        boolean bearer = scheme.equalsIgnoreCase(BEARER);
        if (!bearer && !scheme.equalsIgnoreCase(BASIC)) {
            return allowed();
        }
        if (separator < 0 || authorization.charAt(separator) != ' ') {
            return refused();
        }
        String value = authorization.substring(separator + 1);
        if (bearer) {
            return COMPACT_JWS.matcher(value).matches() && !isRevokedOrUnknown(value) ? allowed() : refused();
        }
        // The proxy also takes a JWT as either part of Basic credentials.
        String credentials;
        try {
            credentials = new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return refused();
        }
        for (String part : credentials.split(":", 2)) {
            // An upstream may strip whitespace or base64 padding before reading a token, so a part
            // that is a JWT once stripped is refused unless it already was one.
            boolean jws = COMPACT_JWS.matcher(part).matches();
            if (!jws && COMPACT_JWS.matcher(part.replaceAll("[\\s=]", "")).matches()) {
                return refused();
            }
            if (jws && isRevokedOrUnknown(part)) {
                return refused();
            }
        }
        return allowed();
    }

    private boolean isRevokedOrUnknown(String encodedToken) {
        AccessToken token = session.tokens().decode(encodedToken, AccessToken.class);
        if (token == null || !Boolean.TRUE.equals(token.getOtherClaims().get(LongLivedTokenAdminResource.LONG_LIVED_CLAIM))) {
            return false;
        }
        RealmModel realm = session.getContext().getRealm();
        LongLivedTokenEntity entity = session.getProvider(JpaConnectionProvider.class).getEntityManager()
                .find(LongLivedTokenEntity.class, token.getId());
        return entity == null || !entity.getRealmId().equals(realm.getId()) || entity.isRevoked();
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
