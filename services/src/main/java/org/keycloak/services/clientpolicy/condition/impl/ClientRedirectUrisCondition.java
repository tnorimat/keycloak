package org.keycloak.services.clientpolicy.condition.impl;

import java.util.Collections;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

public class ClientRedirectUrisCondition implements ClientPolicyCondition {
    private static final Logger logger = Logger.getLogger(ClientRedirectUrisCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientRedirectUrisCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public boolean isEvaluatedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.ADMIN_REGISTER:
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.AUTHORIZATION_REQUEST:
            case ClientPolicyEvent.TOKEN_REQUEST:
                return true;
        }
        return false;
    }

    // on Admin REST API Registration access for creating client
    @Override
    public boolean isSatisfiedOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for creating client");
        return isUrlsMatched(rep.getRedirectUris());
    };

    // on Dynamic Registration Endpoint access for creating client
    @Override
    public boolean isSatisfiedOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) {
        ClientPolicyLogger.log(logger, "Dynamic Registration Endpoint access for creating client");
        return isUrlsMatched(context.getClient().getRedirectUris());
    };

    // on Authorization Endpoint access for authorization request
    @Override
    public boolean isSatisfiedOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) {
        ClientPolicyLogger.log(logger, "Authorization Endpoint access for authorization request");
        return isUrlsMatched(Collections.singletonList(redirectUri));
    }

    // on Token Endpoint access for token request
    @Override
    public boolean isSatisfiedOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) {
        ClientPolicyLogger.log(logger, "Token Endpoint access for token request");
        return isUrlsMatched(Collections.singletonList(parseResult.getClientSession().getRedirectUri()));
    }

    private boolean isUrlsMatched(List<String> redirectUris) {
        redirectUris.stream().forEach(i -> ClientPolicyLogger.log(logger, "client redirect uri = " + i));
        componentModel.getConfig().get(ClientRedirectUrisConditionFactory.URIS).stream().forEach(i -> ClientPolicyLogger.log(logger, "client redirect uri expected = " + i));

        boolean isMatched = componentModel.getConfig().get(ClientRedirectUrisConditionFactory.URIS).stream().anyMatch(i->{
            return redirectUris.stream().anyMatch(j->j.equals(i));
            });
        if (isMatched) {
            ClientPolicyLogger.log(logger, "client redirect uri matched.");
        } else {
            ClientPolicyLogger.log(logger, "client redirect uri unmatched.");
        }
        return isMatched;
    }

}
