package org.keycloak.services.clientpolicy.executor.impl;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

public class ClientAuthenticationExecutor extends AbstractObsoleteClientPolicyExecutor {
    private static final Logger logger = Logger.getLogger(ClientAuthenticationExecutor.class);

    public ClientAuthenticationExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.DYNAMIC_UPDATE:
            case ClientPolicyEvent.ADMIN_REGISTER:
            case ClientPolicyEvent.ADMIN_UPDATE:
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
        verifyClientAuthenticationMethod(context.getClient().getClientAuthenticatorType());
    }

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public void executeOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client)  throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Dynamic Client Registration Endpoint - updating client");
        if (context.getClient().getClientAuthenticatorType() != null) {
            verifyClientAuthenticationMethod(context.getClient().getClientAuthenticatorType());
        } else {
            verifyClientAuthenticationMethod(client.getClientAuthenticatorType());
        }
    }
 
    // on Admin REST API Registration access for creating client
    @Override
    public void executeOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Admin REST API Registration - creating client");
        verifyClientAuthenticationMethod(rep.getClientAuthenticatorType());
    };

    // on Admin REST API Registration access for updating client
    @Override
    public void executeOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Admin REST API Registration - updating client");
        if (rep.getClientAuthenticatorType() != null) {
            verifyClientAuthenticationMethod(rep.getClientAuthenticatorType());
        } else {
            verifyClientAuthenticationMethod(client.getClientAuthenticatorType());
        }
    };

    private void verifyClientAuthenticationMethod(String clientAuthenticatorType) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Authenticator Type = " + clientAuthenticatorType);
        List<String> acceptableClientAuthn = componentModel.getConfig().getList(ClientAuthenticationExecutorFactory.CLIENT_AUTHNS);
        if (acceptableClientAuthn != null && acceptableClientAuthn.stream().anyMatch(i->i.equals(clientAuthenticatorType))) return;
        throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: token_endpoint_auth_method");
    }
}
