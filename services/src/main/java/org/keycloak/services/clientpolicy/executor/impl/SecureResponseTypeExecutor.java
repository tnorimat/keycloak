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

public class SecureResponseTypeExecutor  extends AbstractObsoleteClientPolicyExecutor {
    private static final Logger logger = Logger.getLogger(SecureResponseTypeExecutor.class);

    public SecureResponseTypeExecutor(KeycloakSession session, ComponentModel componentModel) {
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

        if (parsedResponseType.hasResponseType(OIDCResponseType.CODE) && parsedResponseType.hasResponseType(OIDCResponseType.ID_TOKEN)) {
            ClientPolicyLogger.log(logger, "Passed.response_type = code id_token");
            return;
        }

        if (parsedResponseType.hasResponseType(OIDCResponseType.CODE) && parsedResponseType.hasResponseType(OIDCResponseType.ID_TOKEN) && parsedResponseType.hasResponseType(OIDCResponseType.TOKEN)) {
            ClientPolicyLogger.log(logger, "Passed.response_type = code id_token token");
            return;
        }

        ClientPolicyLogger.log(logger, "invalid response_type = " + parsedResponseType);
        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "invalid response_type");

    }
}
