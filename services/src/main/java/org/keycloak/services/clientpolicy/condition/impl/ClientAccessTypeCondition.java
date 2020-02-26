package org.keycloak.services.clientpolicy.condition.impl;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;

public class ClientAccessTypeCondition implements ClientPolicyCondition {
    private static final Logger logger = Logger.getLogger(ClientAccessTypeCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientAccessTypeCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    private String getClientAccessType() {
        ClientModel client = session.getContext().getClient();
        if (client == null) return null;

        if (client.isPublicClient()) return ClientAccessTypeConditionFactory.TYPE_PUBLIC;
        if (client.isBearerOnly()) return ClientAccessTypeConditionFactory.TYPE_BEARERONLY;
        else return ClientAccessTypeConditionFactory.TYPE_CONFIDENTIAL;
    }

    @Override
    public boolean isEvaluatedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.AUTHORIZATION_REQUEST:
            case ClientPolicyEvent.TOKEN_REQUEST:
                return true;
        }
        return false;
    }

    // on Authorization Endpoint access for authorization request
    @Override
    public boolean isSatisfiedOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) {
        ClientPolicyLogger.log(logger, "Authz Endpoint - authz request");
        return isClientAccessTypeMatched();
    }

    // on Token Endpoint access for token request
    @Override
    public boolean isSatisfiedOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) {
        ClientPolicyLogger.log(logger, "Token Endpoint - token request");
        return isClientAccessTypeMatched();
    }

    private boolean isClientAccessTypeMatched() {
        final String accessType = getClientAccessType();
        ClientPolicyLogger.log(logger, "client access type = " + accessType);
        componentModel.getConfig().get(ClientAccessTypeConditionFactory.TYPE).stream().forEach(i -> ClientPolicyLogger.log(logger, "client access type expected = " + i));

        boolean isMatched = componentModel.getConfig().get(ClientAccessTypeConditionFactory.TYPE).stream().anyMatch(i -> i.equals(accessType));
        if (isMatched) {
            ClientPolicyLogger.log(logger, "client access type matched.");
        } else {
            ClientPolicyLogger.log(logger, "client access type unmatched.");
        }
        return isMatched;
    }
}
