/*
 *
 *  * Copyright 2021  Red Hat, Inc. and/or its affiliates
 *  * and other contributors as indicated by the @author tags.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.keycloak.protocol.oidc.grants.management.endpoints;

import org.apache.commons.lang.StringUtils;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionCrossDCManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.util.MtlsHoKTokenUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Collections;

/**
 * Grant management for OAuth 2.0 endpoint
 */
public class GrantEndpoint implements RealmResourceProvider {

    public static final String GRANT_MANAGEMENT_QUERY = "grant_management_query";
    public static final String GRANT_MANAGEMENT_REVOKE = "grant_management_revoke";

    protected static final Logger logger = Logger.getLogger(GrantEndpoint.class);

    @Context
    private HttpRequest request;

    @Context
    private HttpResponse response;

    @Context
    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    private final org.keycloak.protocol.oidc.TokenManager tokenManager;
    private final AppAuthManager appAuthManager;
    private final RealmModel realm;
    private ClientModel clientModel;
    private UserModel userModel;
    private EventBuilder event;
    private Cors cors;




    public GrantEndpoint(RealmModel realm, EventBuilder event, org.keycloak.protocol.oidc.TokenManager tokenManager) {
        this.realm = realm;
        this.event = event;
        this.tokenManager = tokenManager;
        this.appAuthManager = new AppAuthManager();
    }


    /**
     * This endpoint is used to get a grant.
     *
     * @param grandId the grant id
     * @return a Grant
     */
    @Path("{grant_id}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Response query(@PathParam("grant_id") String grandId, @Context final HttpHeaders headers) {
        logger.trace("query request");

        String accessToken = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
        checkToken(accessToken, GRANT_MANAGEMENT_QUERY);

        GrantService grantService = session.getProvider(GrantService.class);


        UserGrantModel grant = null;
        try {
            grant = grantService.getGrantByGrantId(realm, grandId, userModel.getId());
        } catch (ModelException e) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, e.getMessage(), Response.Status.BAD_REQUEST);
        }


        return Response.status(Response.Status.OK)
                .entity(grant)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    /**
     * This endpoint is used to delete a grant.
     *
     * @param grandId the grant id
     * @return returns 204 if deleted
     */
    @Path("{grant_id}")
    @DELETE
    public Response revoke(@PathParam("grant_id") String grandId, @Context final HttpHeaders headers) {
        logger.info("revoke grant");
        event.event(EventType.REVOKE_GRANT);

        String accessToken = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
        checkToken(accessToken, GRANT_MANAGEMENT_REVOKE);

        GrantService grantService = session.getProvider(GrantService.class);
        boolean delete = grantService.revokeGrantByGrantId(realm, grandId, userModel.getId());

        if (!delete) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "Grant not found", Response.Status.BAD_REQUEST);
        }
        return Response.noContent().build();
    }

    @Override
    public Object getResource() {
        return null;
    }

    @Override
    public void close() {
    }

    private void checkToken(String tokenString, String grantManagementAction) {
        cors = Cors.add(request).auth().allowedMethods(request.getHttpMethod()).auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        EventBuilder event = new EventBuilder(realm, session, clientConnection)
                .event(EventType.USER_INFO_REQUEST)
                .detail(Details.AUTH_METHOD, Details.VALIDATE_ACCESS_TOKEN);

        if (tokenString == null) {
            event.error(Errors.INVALID_TOKEN);
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "Token not provided", Response.Status.BAD_REQUEST);
        }

        AccessToken token;
        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class).withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, verifier.getHeader().getAlgorithm().name()).verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);

            token = verifier.verify().getToken();

            String scope = token.getScope();
            if (!StringUtils.contains(scope, grantManagementAction)) {
                event.error(Errors.INVALID_TOKEN);
                throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Token verification failed");
            }

            clientModel = realm.getClientByClientId(token.getIssuedFor());
            if (clientModel == null) {
                event.error(Errors.CLIENT_NOT_FOUND);
                throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "Client not found", Response.Status.BAD_REQUEST);
            }

            cors.allowedOrigins(session, clientModel);

            TokenVerifier.createWithoutSignature(token)
                    .withChecks(TokenManager.NotBeforeCheck.forModel(clientModel))
                    .verify();
        } catch (VerificationException e) {
            if (clientModel == null) {
                cors.allowAllOrigins();
            }
            event.error(Errors.INVALID_TOKEN);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Token verification failed");
        }

        if (!clientModel.getProtocol().equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new CorsErrorResponseException(cors, Errors.INVALID_CLIENT, "Wrong client protocol.", Response.Status.BAD_REQUEST);
        }

        session.getContext().setClient(clientModel);

        event.client(clientModel);

        if (!clientModel.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "Client disabled", Response.Status.BAD_REQUEST);
        }

        UserSessionModel userSession = findValidSession(token, event, clientModel);

         userModel = userSession.getUser();
        if (userModel == null) {
            event.error(Errors.USER_NOT_FOUND);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "User not found", Response.Status.BAD_REQUEST);
        }

        event.user(userModel)
                .detail(Details.USERNAME, userModel.getUsername());

        // KEYCLOAK-6771 Certificate Bound Token
        // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3
        if (OIDCAdvancedConfigWrapper.fromClientModel(clientModel).isUseMtlsHokToken()) {
            if (!MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, request, session)) {
                event.error(Errors.NOT_ALLOWED);
                throw newUnauthorizedErrorResponseException(OAuthErrorException.UNAUTHORIZED_CLIENT, "Client certificate missing, or its thumbprint and one in the refresh token did NOT match");
            }
        }

        event.success();
    }

    // This method won't add allowedOrigins to the cors. Assumption is that allowedOrigins are already set to the "cors" object when this method is called
    private CorsErrorResponseException newUnauthorizedErrorResponseException(String oauthError, String errorMessage) {
        // See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
        response.getOutputHeaders().put(HttpHeaders.WWW_AUTHENTICATE, Collections.singletonList(String.format("Bearer realm=\"%s\", error=\"%s\", error_description=\"%s\"", realm.getName(), oauthError, errorMessage)));
        return new CorsErrorResponseException(cors, oauthError, errorMessage, Response.Status.UNAUTHORIZED);
    }

    private UserSessionModel findValidSession(AccessToken token, EventBuilder event, ClientModel client) {
        if (token.getSessionState() == null) {
            return createTransientSessionForClient(token, client);
        }

        UserSessionModel userSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), false, client.getId());
        UserSessionModel offlineUserSession = null;
        if (AuthenticationManager.isSessionValid(realm, userSession)) {
            checkTokenIssuedAt(token, userSession, event);
            event.session(userSession);
            return userSession;
        } else {
            offlineUserSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), true, client.getId());
            if (AuthenticationManager.isOfflineSessionValid(realm, offlineUserSession)) {
                checkTokenIssuedAt(token, offlineUserSession, event);
                event.session(offlineUserSession);
                return offlineUserSession;
            }
        }

        if (userSession == null && offlineUserSession == null) {
            event.error(Errors.USER_SESSION_NOT_FOUND);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_REQUEST, "User session not found or doesn't have client attached on it");
        }

        if (userSession != null) {
            event.session(userSession);
        } else {
            event.session(offlineUserSession);
        }

        event.error(Errors.SESSION_EXPIRED);
        throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Session expired");
    }

    private void checkTokenIssuedAt(AccessToken token, UserSessionModel userSession, EventBuilder event) throws CorsErrorResponseException {
        if (token.getIssuedAt() + 1 < userSession.getStarted()) {
            event.error(Errors.INVALID_TOKEN);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Stale token");
        }
    }

    private UserSessionModel createTransientSessionForClient(AccessToken token, ClientModel client) {
        // create a transient session
        UserModel user = TokenManager.lookupUserFromStatelessToken(session, realm, token);
        if (user == null) {
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_REQUEST, "User not found");
        }
        UserSessionModel userSession = session.sessions().createUserSession(KeycloakModelUtils.generateId(), realm, user, user.getUsername(), clientConnection.getRemoteAddr(),
                ServiceAccountConstants.CLIENT_AUTH, false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);
        // attach an auth session for the client
        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().createRootAuthenticationSession(realm);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(userSession.getUser());
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        AuthenticationManager.setClientScopesInSession(authSession);
        TokenManager.attachAuthenticationSession(session, userSession, authSession);
        return userSession;
    }

}