package org.keycloak.services.clientpolicy.executor.impl;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class HoKTokenEnforceExecutor extends AbstractObsoleteClientPolicyExecutor {

    private static final Logger logger = Logger.getLogger(HoKTokenEnforceExecutor.class);

    public HoKTokenEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.DYNAMIC_UPDATE:
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
        verifyHoKTokenSetting(context);
    }

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public void executeOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Dynamic Client Registration Endpoint - updating client");
        verifyHoKTokenSetting(context);
    }

    private void verifyHoKTokenSetting(ClientRegistrationContext context) throws ClientPolicyException {
        if (!OIDCAdvancedConfigWrapper.fromClientRepresentation(context.getClient()).isUseMtlsHokToken()) {
            ClientPolicyLogger.log(logger, "NG. Not use Holder-of-Key Token.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter: tls_client_certificate_bound_access_tokens");
        }
        ClientPolicyLogger.log(logger, "Passed. Use Holder-of-Key Token.");
    }
}
