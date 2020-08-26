package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.AuthorizationRequestContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;

public class SecureResponseTypeExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(SecureResponseTypeExecutor.class);

    protected final KeycloakSession session;
    protected final ComponentModel componentModel;

    public SecureResponseTypeExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case AUTHORIZATION_REQUEST:
                AuthorizationRequestContext authorizationRequestContext = (AuthorizationRequestContext)context;
                executeOnAuthorizationRequest(authorizationRequestContext.getparsedResponseType(),
                    authorizationRequestContext.getAuthorizationEndpointRequest(),
                    authorizationRequestContext.getRedirectUri());
                break;
            default:
                return;
        }
    }

    // on Authorization Endpoint access for authorization request
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

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

}
