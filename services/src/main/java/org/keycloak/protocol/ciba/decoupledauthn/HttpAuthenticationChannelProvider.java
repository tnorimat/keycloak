/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.protocol.ciba.decoupledauthn;

import java.io.IOException;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ciba.CIBAAuthReqId;
import org.keycloak.protocol.ciba.CIBAConstants;
import org.keycloak.protocol.ciba.endpoints.request.BackchannelAuthenticationRequest;
import org.keycloak.protocol.ciba.resolvers.CIBALoginUserResolver;
import org.keycloak.protocol.ciba.utils.CIBAAuthReqIdParser;
import org.keycloak.protocol.ciba.utils.DecoupledAuthStatus;
import org.keycloak.protocol.ciba.utils.DecoupledAuthnResult;
import org.keycloak.protocol.ciba.utils.DecoupledAuthnResultParser;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;

public class HttpAuthenticationChannelProvider extends HttpAuthenticationChannelProviderBase {

    private static final Logger logger = Logger.getLogger(HttpAuthenticationChannelProvider.class);

    protected final String httpAuthenticationRequestUri;

    public HttpAuthenticationChannelProvider(KeycloakSession session, String httpAuthenticationRequestUri) {
        super(session);
        this.httpAuthenticationRequestUri = httpAuthenticationRequestUri;
    }

    protected String scope;
    protected String userSessionIdWillBeCreated;
    protected String userIdToBeAuthenticated;
    protected String authResultId;
    protected int expiration;

    @Override
    protected String getScope() {
        return scope;
    }

    @Override
    protected String getUserSessionIdWillBeCreated() {
        return userSessionIdWillBeCreated;
    }

    @Override
    protected String getUserIdToBeAuthenticated() {
        return userIdToBeAuthenticated;
    }

    @Override
    protected String getAuthResultId() {
        return authResultId;
    }

    @Override
    protected int getExpiration() {
        return expiration;
    }

    @Override
    protected Response verifyDecoupledAuthnResult() {
        String decoupledAuthId = formParams.getFirst(HttpAuthenticationChannelProvider.DECOUPLED_AUTHN_ID);
        ParseResult parseResult = parseDecoupledAuthId(session, decoupledAuthId, event);

        if (parseResult.isIllegalDecoupledAuthId()) {
            event.error(Errors.INVALID_INPUT);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.UNKNOWN);
            // decoupled auth id format is invalid or it has already been used
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "invalid decoupled authn id", Response.Status.BAD_REQUEST);
        } else if (parseResult.isExpiredDecoupledAuthId()) {
            event.error(Errors.SESSION_EXPIRED);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.EXPIRED);
            return cors.builder(Response.ok("", MediaType.APPLICATION_JSON_TYPE)).build();
        }

        CIBAAuthReqId decoupledAuthIdJwt = parseResult.decoupledAuthIdJwt();
        authResultId = decoupledAuthIdJwt.getAuthResultId();
        scope = decoupledAuthIdJwt.getScope();
        expiration = decoupledAuthIdJwt.getExp().intValue();
        userSessionIdWillBeCreated = decoupledAuthIdJwt.getSessionState();
        userIdToBeAuthenticated = decoupledAuthIdJwt.getSubject();
        // to bind Client Session of CD(Consumption Device) with User Session, set CD's Client Model to this class member "client".
        client = realm.getClientByClientId(decoupledAuthIdJwt.getIssuedFor());

        CIBALoginUserResolver resolver = session.getProvider(CIBALoginUserResolver.class);
        if (resolver == null) {
            throw new RuntimeException("CIBA Login User Resolver not setup properly.");
        }
        String userIdAuthenticated = resolver.getUserFromInfoUsedByAuthentication(formParams.getFirst(HttpAuthenticationChannelProvider.DECOUPLED_AUTHN_USER_INFO)).getId();
        if (!userIdToBeAuthenticated.equals(userIdAuthenticated)) {
            event.error(Errors.DIFFERENT_USER_AUTHENTICATED);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.DIFFERENT);
            return cors.builder(Response.status(Status.BAD_REQUEST)).build();
        }

        String authResult = formParams.getFirst(HttpAuthenticationChannelProvider.DECOUPLED_AUTHN_RESULT);
        if (authResult == null) {
            event.error(Errors.INVALID_INPUT);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.UNKNOWN);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "authentication result not specified", Response.Status.BAD_REQUEST);
        } else if (authResult.equals(DecoupledAuthStatus.FAILED)) {
            event.error(Errors.NOT_LOGGED_IN);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.FAILED);
        } else if (authResult.equals(DecoupledAuthStatus.CANCELLED)) {
            event.error(Errors.NOT_ALLOWED);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.CANCELLED);
        } else if (authResult.equals(DecoupledAuthStatus.UNAUTHORIZED)) {
            event.error(Errors.CONSENT_DENIED);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.UNAUTHORIZED);
        } else if (authResult.equals(DecoupledAuthStatus.SUCCEEDED)) {
            return null;
        } else {
            event.error(Errors.INVALID_INPUT);
            persistDecoupledAuthenticationResult(DecoupledAuthStatus.UNKNOWN);
        }
        return cors.builder(Response.ok("", MediaType.APPLICATION_JSON_TYPE)).build();
    }

    @Override
    public void requestAuthentication(ClientModel client, BackchannelAuthenticationRequest request, int expiresIn, String authResultId, String userSessionIdWillBeCreated) {
        // create JWT formatted/JWS signed/JWE encrypted Decoupled Auth ID by the same manner in creating auth_req_id
        // Decoupled Auth ID binds Backchannel Authentication Request with Authentication by AD(Authentication Device).
        // By including userSessionIdWillBeCreated. keycloak can create UserSession whose ID is userSessionIdWillBeCreated on Decoupled Authentication Callback Endpoint,
        // which can bind userSessionIdWillBeCreated (namely, Backchannel Authentication Request) with authenticated UserSession.
        // By including authResultId, keycloak can create Decoupled Authentication Result of Authentication by AD on Decoupled Authentication Callback Endpoint,
        // which can bind authResultId with Decoupled Authentication Result of Authentication by AD.
        // By including client_id, Decoupled Authentication Callback Endpoint can recognize the CD(Consumption Device) who sent Backchannel Authentication Request.

        // The following scopes should be displayed on AD(Authentication Device):
        // 1. scopes specified explicitly as query parameter in the authorization request
        // 2. scopes specified implicitly as default client scope in keycloak

        checkAuthenticationChannel();

        CIBALoginUserResolver resolver = session.getProvider(CIBALoginUserResolver.class);
        if (resolver == null) {
            throw new RuntimeException("CIBA Login User Resolver not setup properly.");
        }
        String authRequestedUserHint = realm.getCIBAPolicy().getAuthRequestedUserHint();
        UserModel user;
        if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT)) {
            user = resolver.getUserFromLoginHint(request.getLoginHint());
        } else if (authRequestedUserHint.equals(CIBAConstants.ID_TOKEN_HINT)) {
            user = resolver.getUserFromLoginHint(request.getIdTokenHint());
        } else if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT_TOKEN)) {
            user = resolver.getUserFromLoginHint(request.getLoginHintToken());
        } else {
            throw new RuntimeException("CIBA invalid Authentication Requested User Hint.");
        }
        String infoUsedByAuthentication = resolver.getInfoUsedByAuthentication(user);

        StringBuilder scopeBuilder = new StringBuilder();
        Map<String, ClientScopeModel> defaultScopesMap = client.getClientScopes(true, true);
        defaultScopesMap.forEach((key, value)->{if (value.isDisplayOnConsentScreen()) scopeBuilder.append(value.getName()).append(" ");});
        String defaultClientScope = scopeBuilder.toString();

        CIBAAuthReqId decoupledAuthIdJwt = new CIBAAuthReqId();
        decoupledAuthIdJwt.id(KeycloakModelUtils.generateId());
        decoupledAuthIdJwt.setScope(request.getScope());
        decoupledAuthIdJwt.setSessionState(userSessionIdWillBeCreated);
        decoupledAuthIdJwt.setAuthResultId(authResultId);
        decoupledAuthIdJwt.issuedNow();
        decoupledAuthIdJwt.issuer(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        decoupledAuthIdJwt.audience(decoupledAuthIdJwt.getIssuer());
        decoupledAuthIdJwt.subject(user.getId());
        decoupledAuthIdJwt.exp(Long.valueOf(Time.currentTime() + expiresIn));
        //decoupledAuthIdJwt.issuedFor(Decoupled Auth Server's client_id); TODO
        decoupledAuthIdJwt.issuedFor(client.getClientId()); // TODO : set CD's client_id intentionally, not Decoupled Auth Server. It is not good idea so that client_id field should be added.
        String decoupledAuthId = CIBAAuthReqIdParser.persistAuthReqId(session, decoupledAuthIdJwt);

        try {
            SimpleHttp simpleHttp = SimpleHttp.doPost(httpAuthenticationRequestUri, session)
                .param(DECOUPLED_AUTHN_ID, decoupledAuthId)
                .param(DECOUPLED_AUTHN_USER_INFO, infoUsedByAuthentication)
                .param(DECOUPLED_AUTHN_IS_CONSENT_REQUIRED, Boolean.toString(client.isConsentRequired()))
                .param(CIBAConstants.SCOPE, request.getScope())
                .param(DECOUPLED_DEFAULT_CLIENT_SCOPE, defaultClientScope)
                .param(CIBAConstants.BINDING_MESSAGE, request.getBindingMessage());

            int status = completeDecoupledAuthnRequest(simpleHttp, user, client, request, expiresIn, authResultId).asStatus();

            if (status != Status.CREATED.getStatusCode()) {
                // To terminate CIBA flow, set Auth Result as unknown
                DecoupledAuthnResult decoupledAuthnResult = new DecoupledAuthnResult(Time.currentTime() + expiresIn, DecoupledAuthStatus.UNKNOWN);
                DecoupledAuthnResultParser.persistDecoupledAuthnResult(session, authResultId.toString(), decoupledAuthnResult, Time.currentTime() + expiresIn);
            }
        } catch (IOException ioe) {
            throw new RuntimeException("Decoupled Authn Request URI Access failed.", ioe);
        }
    }

    /**
     * Extension point to allow subclass to override this method in order to add datas to post to decoupled server.
     */
    protected SimpleHttp completeDecoupledAuthnRequest(SimpleHttp simpleHttp, UserModel user, ClientModel client, BackchannelAuthenticationRequest request, int expiresIn, String authResultId) {
        return simpleHttp;
    }

    protected void checkAuthenticationChannel() {
        if (httpAuthenticationRequestUri == null || !(httpAuthenticationRequestUri.startsWith("http://") || httpAuthenticationRequestUri.startsWith("https://"))) {
            throw new RuntimeException("Authentication Channel Request URI not set properly.");
        }
    }

    public static final String DECOUPLED_AUTHN_ID = "decoupled_auth_id";
    public static final String DECOUPLED_AUTHN_USER_INFO = "user_info";
    public static final String DECOUPLED_AUTHN_RESULT = "auth_result";
    public static final String DECOUPLED_AUTHN_IS_CONSENT_REQUIRED = "is_consent_required";
    public static final String DECOUPLED_DEFAULT_CLIENT_SCOPE = "default_client_scope";

    public ParseResult parseDecoupledAuthId(KeycloakSession session, String encodedJwt, EventBuilder event) {
        CIBAAuthReqId decoupledAuthIdJwt = null;
        try {
            decoupledAuthIdJwt = CIBAAuthReqIdParser.getAuthReqIdJwt(session, encodedJwt);
        } catch (Exception e) {
            logger.warnf("illegal format of decoupled_auth_id : %s", e.getMessage());
            return (new ParseResult(null)).illegalDecoupledAuthId();
        }
        ParseResult result = new ParseResult(decoupledAuthIdJwt);

        event.detail(Details.CODE_ID, result.decoupledAuthIdJwt.getSessionState());
        event.session(result.decoupledAuthIdJwt.getSessionState());

        // Finally doublecheck if code is not expired
        if (Time.currentTime() > result.decoupledAuthIdJwt.getExp().intValue()) {
            return result.expiredDecoupledAuthId();
        }

        return result;
    }

    public class ParseResult {

        private final CIBAAuthReqId decoupledAuthIdJwt;

        private boolean isIllegalDecoupledAuthId= false;
        private boolean isExpiredDecoupledAuthId = false;

        private ParseResult(CIBAAuthReqId decoupledAuthIdJwt) {
            this.decoupledAuthIdJwt = decoupledAuthIdJwt;
        }

        public CIBAAuthReqId decoupledAuthIdJwt() {
            return decoupledAuthIdJwt;
        }

        public boolean isIllegalDecoupledAuthId() {
            return isIllegalDecoupledAuthId;
        }

        public boolean isExpiredDecoupledAuthId() {
            return isExpiredDecoupledAuthId;
        }

        private ParseResult illegalDecoupledAuthId() {
            this.isIllegalDecoupledAuthId = true;
            return this;
        }

        private ParseResult expiredDecoupledAuthId() {
            this.isExpiredDecoupledAuthId = true;
            return this;
        }
    }
}
