package org.keycloak.services.clientpolicy.condition.impl;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

public class AuthnMethodsCondition implements ClientPolicyCondition {

    private static final Logger logger = Logger.getLogger(AuthnMethodsCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public AuthnMethodsCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public boolean isEvaluatedOnEvent(String event) {
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
    public boolean isSatisfiedOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) {
        ClientPolicyLogger.log(logger, "Dynamic Registration Endpoint - creating client");
        return authType == null ? false : isAuthMethodMatched(authType.name());
    }

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public boolean isSatisfiedOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client) {
        ClientPolicyLogger.log(logger, "Dynamic Registration Endpoint - updating client");
        return authType == null ? false : isAuthMethodMatched(authType.name());
    }

    // on Admin REST API Registration access for creating client
    @Override
    public boolean isSatisfiedOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for creating client");
        return isAuthMethodMatched(AuthnMethodsConditionFactory.BY_ADMIN_REST_API);
    };

    // on Admin REST API Registration access for updating client
    @Override
    public boolean isSatisfiedOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for updating client");
        return isAuthMethodMatched(AuthnMethodsConditionFactory.BY_ADMIN_REST_API);
    };

    private boolean isAuthMethodMatched(String authMethod) {
        if (authMethod == null) return false;

        ClientPolicyLogger.log(logger, "auth method = " + authMethod);
        componentModel.getConfig().get(AuthnMethodsConditionFactory.AUTH_METHOD).stream().forEach(i -> ClientPolicyLogger.log(logger, "auth method expected = " + i));

        boolean isMatched = componentModel.getConfig().get(AuthnMethodsConditionFactory.AUTH_METHOD).stream().anyMatch(i -> i.equals(authMethod));
        if (isMatched) {
            ClientPolicyLogger.log(logger, "auth method matched.");
        } else {
            ClientPolicyLogger.log(logger, "auth method unmatched.");
        }
        return isMatched;
    }
}
