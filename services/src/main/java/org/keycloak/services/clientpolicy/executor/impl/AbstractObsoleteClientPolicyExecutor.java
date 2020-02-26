package org.keycloak.services.clientpolicy.executor.impl;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

public abstract class AbstractObsoleteClientPolicyExecutor implements ClientPolicyExecutor {

    protected static final Logger logger = Logger.getLogger(AbstractObsoleteClientPolicyExecutor.class);

    protected final KeycloakSession session;
    protected final ComponentModel componentModel;

    public AbstractObsoleteClientPolicyExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    // on Dynamic Registration Endpoint access for creating client
    @Override
    public void executeOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Dynamic Client Registration Endpoint - creating client : Do Nothing");
    }

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public void executeOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Dynamic Client Registration Endpoint - updating client : Do Nothing");
    }

    // on Authorization Endpoint access for authorization request
    @Override
    public void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Authorization Endpoint access for authorization request : Do Nothing");
    }

    // on Token Endpoint access for token request
    @Override
    public void executeOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Token Endpoint access for token request : Do Nothing");
    }

    // on Admin REST API Registration access for creating client
    @Override
    public void executeOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Admin REST API Registration Endpoint - creating client : Do Nothing");
    }

    // on Admin REST API Registration access for updating client
    @Override
    public void executeOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Admin REST API Registration Endpoint - updating client : Do Nothing");
    }

}
