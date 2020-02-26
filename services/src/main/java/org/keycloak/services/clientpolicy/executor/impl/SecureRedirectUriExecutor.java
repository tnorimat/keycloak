package org.keycloak.services.clientpolicy.executor.impl;

import java.util.List;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class SecureRedirectUriExecutor extends AbstractObsoleteClientPolicyExecutor {

    private static final Logger logger = Logger.getLogger(SecureRedirectUriExecutor.class);

    public SecureRedirectUriExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.AUTHORIZATION_REQUEST:
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
        List<String> redirectUris = context.getClient().getRedirectUris();
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: redirect_uris");
        }
        for(String redirectUri : redirectUris) {
            ClientPolicyLogger.log(logger, "Redirect URI = " + redirectUri);
            if (redirectUri.startsWith("http://")) {
                throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: redirect_uris");
            }
            if (redirectUri.contains("*")) {
                throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: redirect_uris");
            }
        }
    }

    // on Authorization Endpoint access for authorization request
    @Override
    public void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Authz Endpoint - authz request");
        ClientModel client = session.getContext().getClient();
        Set<String> registeredUris = client.getRedirectUris();
        String redirectUriParam = request.getRedirectUriParam();
        ClientPolicyLogger.log(logger, "client_id = " + client.getClientId());
        ClientPolicyLogger.log(logger, "redirect_uri = " + redirectUriParam);
        registeredUris.stream().forEach(i -> {ClientPolicyLogger.log(logger, "registerd_uri = " + i);});
        if(!registeredUris.stream().anyMatch(s -> s.equals(redirectUriParam))) {
            ClientPolicyLogger.log(logger, "Not Matched.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter: redirect_uri");
        }
        ClientPolicyLogger.log(logger, "Matched.");
    }
}
