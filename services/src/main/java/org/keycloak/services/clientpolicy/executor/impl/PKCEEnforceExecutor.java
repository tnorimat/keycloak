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

package org.keycloak.services.clientpolicy.executor.impl;

import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class PKCEEnforceExecutor extends AbstractObsoleteClientPolicyExecutor {

    private static final Logger logger = Logger.getLogger(PKCEEnforceExecutor.class);

    private static final Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile("^[0-9a-zA-Z\\-\\.~_]+$");
    private static final Pattern VALID_CODE_VERIFIER_PATTERN  = Pattern.compile("^[0-9a-zA-Z\\-\\.~_]+$");

    public PKCEEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.AUTHORIZATION_REQUEST:
            case ClientPolicyEvent.TOKEN_REQUEST:
                return true;
        }
        return false;
    }

    // on Dynamic Registration Endpoint access for creating client
    @Override
    public void executeOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Dynamic Client Registration Endpoint - creating client");
        ClientPolicyLogger.log(logger, "Code Challenge Method from client = " + OIDCAdvancedConfigWrapper.fromClientRepresentation(context.getClient()).getPkceCodeChallengeMethod());
        OIDCAdvancedConfigWrapper.fromClientRepresentation(context.getClient()).setPkceCodeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        ClientPolicyLogger.log(logger, "Enforce S256.");
    }

    // on Authorization Endpoint access for authorization request
    @Override
    public void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {
        ClientModel client = session.getContext().getClient();
        String codeChallenge = request.getCodeChallenge();
        String codeChallengeMethod = request.getCodeChallengeMethod();
        String pkceCodeChallengeMethod = OIDCAdvancedConfigWrapper.fromClientModel(client).getPkceCodeChallengeMethod();

        ClientPolicyLogger.log(logger, "Authz Endpoint - authz request");
        ClientPolicyLogger.log(logger, "codeChallenge = " + codeChallenge);
        ClientPolicyLogger.log(logger, "codeChallengeMethod = " + codeChallengeMethod);
        ClientPolicyLogger.log(logger, "pkceCodeChallengeMethod = " + pkceCodeChallengeMethod);

        // check whether code challenge method is specified
        if (codeChallengeMethod == null) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Missing parameter: code_challenge_method");
        }

        // check whether specified code challenge method is configured one in advance
        if (!codeChallengeMethod.equals(pkceCodeChallengeMethod)) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter: code challenge method is not configured one");
        }

        // check whether code challenge is specified
        if (codeChallenge == null) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Missing parameter: code_challenge");
        }

        // check whether code challenge is formatted along with the PKCE specification
        if (!isValidPkceCodeChallenge(codeChallenge)) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter: code_challenge");
        }

    }

    // on Token Endpoint access for token request
    @Override
    public void executeOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) throws ClientPolicyException {
        String codeVerifier = params.getFirst(OAuth2Constants.CODE_VERIFIER);
        OAuth2Code codeData = parseResult.getCodeData();
        String codeChallenge = codeData.getCodeChallenge();
        String codeChallengeMethod = codeData.getCodeChallengeMethod();

        ClientPolicyLogger.log(logger, "Token Endpoint - token request");
        ClientPolicyLogger.log(logger, "codeVerifier = " + codeVerifier);
        ClientPolicyLogger.log(logger, "codeChallenge = " + codeChallenge);
        ClientPolicyLogger.log(logger, "codeChallengeMethod = " + codeChallengeMethod);
        checkParamsForPkceEnforcedClient(codeVerifier, codeChallenge, codeChallengeMethod);
    };

    private boolean isValidPkceCodeChallenge(String codeChallenge) {
        if (codeChallenge.length() < OIDCLoginProtocol.PKCE_CODE_CHALLENGE_MIN_LENGTH) {
            return false;
        }
        if (codeChallenge.length() > OIDCLoginProtocol.PKCE_CODE_CHALLENGE_MAX_LENGTH) {
            return false;
        }
        Matcher m = VALID_CODE_CHALLENGE_PATTERN.matcher(codeChallenge);
        return m.matches();
    }

    private void checkParamsForPkceEnforcedClient(String codeVerifier, String codeChallenge, String codeChallengeMethod) throws ClientPolicyException {
        // check whether code verifier is specified
        if (codeVerifier == null) {
            throw new ClientPolicyException(Errors.CODE_VERIFIER_MISSING, "PKCE code verifier not specified");
        }
        verifyCodeVerifier(codeVerifier, codeChallenge, codeChallengeMethod);
    }


    private void verifyCodeVerifier(String codeVerifier, String codeChallenge, String codeChallengeMethod) throws ClientPolicyException {
        // check whether code verifier is formatted along with the PKCE specification

        if (!isValidPkceCodeVerifier(codeVerifier)) {
            throw new ClientPolicyException(Errors.INVALID_CODE_VERIFIER, "PKCE invalid code verifier");
        }

        String codeVerifierEncoded = codeVerifier;
        try {
            // https://tools.ietf.org/html/rfc7636#section-4.2
            // plain or S256
            if (codeChallengeMethod != null && codeChallengeMethod.equals(OAuth2Constants.PKCE_METHOD_S256)) {
                codeVerifierEncoded = generateS256CodeChallenge(codeVerifier);
            } else {
                codeVerifierEncoded = codeVerifier;
            }
        } catch (Exception nae) {
            throw new ClientPolicyException(Errors.PKCE_VERIFICATION_FAILED, "PKCE code verification failed, not supported algorithm specified");
        }
        if (!codeChallenge.equals(codeVerifierEncoded)) {
            throw new ClientPolicyException(Errors.PKCE_VERIFICATION_FAILED, "PKCE verification failed");
        } else {
        }
    }

    private boolean isValidPkceCodeVerifier(String codeVerifier) {
        if (codeVerifier.length() < OIDCLoginProtocol.PKCE_CODE_VERIFIER_MIN_LENGTH) {
            return false;
        }
        if (codeVerifier.length() > OIDCLoginProtocol.PKCE_CODE_VERIFIER_MAX_LENGTH) {
            return false;
        }
        Matcher m = VALID_CODE_VERIFIER_PATTERN.matcher(codeVerifier);
        return m.matches();
    }

    private String generateS256CodeChallenge(String codeVerifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(codeVerifier.getBytes("ISO_8859_1"));
        byte[] digestBytes = md.digest();
        String codeVerifierEncoded = Base64Url.encode(digestBytes);
        return codeVerifierEncoded;
    }

}
