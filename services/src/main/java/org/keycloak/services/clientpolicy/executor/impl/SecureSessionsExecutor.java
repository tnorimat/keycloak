package org.keycloak.services.clientpolicy.executor.impl;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.util.TokenUtil;

public class SecureSessionsExecutor extends AbstractObsoleteClientPolicyExecutor {

    private static final Logger logger = Logger.getLogger(SecureSessionsExecutor.class);

    public SecureSessionsExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.AUTHORIZATION_REQUEST:
                return true;
        }
        return false;
    }

    // on Authorization Endpoint access for authorization request
    @Override
    public void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Authz Endpoint - authz request");
        if (TokenUtil.isOIDCRequest(request.getScope())) {
            if(request.getNonce() == null) {
                ClientPolicyLogger.log(logger, "Missing parameter: nonce");
                throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Missing parameter: nonce");
            }
        } else {
            if(request.getState() == null) {
                ClientPolicyLogger.log(logger, "Missing parameter: scope");
                throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Missing parameter: scope");
            }
        }
        ClientPolicyLogger.log(logger, "Passed.");

    }
}
