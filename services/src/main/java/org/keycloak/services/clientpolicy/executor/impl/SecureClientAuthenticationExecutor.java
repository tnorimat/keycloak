package org.keycloak.services.clientpolicy.executor.impl;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;

public class SecureClientAuthenticationExecutor extends AbstractObsoleteClientPolicyExecutor {

    private static final Logger logger = Logger.getLogger(SecureClientAuthenticationExecutor.class);

    public SecureClientAuthenticationExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.TOKEN_REQUEST:
                return true;
        }
        return false;
    }

    // on Token Endpoint access for token request
    @Override
    public void executeOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Token Endpoint access for token request");
        ClientModel client = session.getContext().getClient();
        if (client.getClientAuthenticatorType().equals(X509ClientAuthenticator.PROVIDER_ID)) {
            ClientPolicyLogger.log(logger, "Passed. client authenticator type = " + X509ClientAuthenticator.PROVIDER_ID);
            return;
        }
        if (client.getClientAuthenticatorType().equals(JWTClientAuthenticator.PROVIDER_ID)) {
            String clientAssertion = params.getFirst(OAuth2Constants.CLIENT_ASSERTION);
            JWSInput jws = null;
            try {
                jws = new JWSInput(clientAssertion);
            } catch (JWSInputException e) {
                throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed signature algorithm.");
            }
            String signatureAlgorithm = jws.getHeader().getAlgorithm().name();
            switch (signatureAlgorithm) {
            case Algorithm.PS256:
            case Algorithm.PS384:
            case Algorithm.PS512:
            case Algorithm.ES256:
            case Algorithm.ES384:
            case Algorithm.ES512:
                ClientPolicyLogger.log(logger, "Passed. client authenticator type = " + JWTClientAuthenticator.PROVIDER_ID + ", signature algorithm = " + signatureAlgorithm);
                return;
            }
        }
        ClientPolicyLogger.log(logger, "NOT allowed client authentication method.");
        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed client authenticathon method.");

    }

}