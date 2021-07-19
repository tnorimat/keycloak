/*
 * Copyright 2021  Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oidc.grants.management;

import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.util.MtlsHoKTokenUtil;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.util.Collections;

public abstract class AbstractGrantManagementEndpoint {

    protected final KeycloakSession session;
    protected final EventBuilder event;
    protected final RealmModel realm;
    protected Cors cors;
    protected ClientModel client;

    @Context
    protected HttpRequest request;

    @Context
    protected HttpResponse response;

    public AbstractGrantManagementEndpoint(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.event = event;
        realm = session.getContext().getRealm();
    }

    protected void checkSsl() {
        ClientConnection clientConnection = session.getContext().getContextObject(ClientConnection.class);

        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https") && realm.getSslRequired().isRequired(clientConnection)) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "HTTPS required", Response.Status.FORBIDDEN);
        }
    }

    protected void checkRealm() {
        if (!realm.isEnabled()) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.ACCESS_DENIED, "Realm not enabled", Response.Status.FORBIDDEN);
        }
    }

    protected void authorizeClient() {
        try {
            AuthorizeClientUtil.ClientAuthResult clientAuth = AuthorizeClientUtil.authorizeClient(session, event, cors);
            client = clientAuth.getClient();

            this.event.client(client);

            cors.allowedOrigins(session, client);

            if (client == null || client.isPublicClient()) {
                throw throwErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Client not allowed.", Response.Status.FORBIDDEN);
            }
        } catch (Exception e) {
            throw throwErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Authentication failed.", Response.Status.UNAUTHORIZED);
        }
    }

    protected void checkToken(String tokenString, String grantManagementAction, String clientId) {
         cors = Cors.add(request).auth().allowedMethods(request.getHttpMethod()).auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        if (tokenString == null) {
            event.error(Errors.INVALID_TOKEN);
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "Token not provided", Response.Status.BAD_REQUEST);
        }

        AccessToken token;
        ClientModel clientModel = null;
        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class).withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, verifier.getHeader().getAlgorithm().name()).verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);

            token = verifier.verify().getToken();

            String scope = token.getScope();
            if (scope != null && !scope.contains(grantManagementAction)) {
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

        if (clientId != null && !clientId.equals(clientModel.getClientId())) {
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Token verification failed");
        }

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

    protected CorsErrorResponseException throwErrorResponseException(String error, String detail, Response.Status status) {
        this.event.detail("detail", detail).error(error);
        return new CorsErrorResponseException(cors, error, detail, status);
    }
}
