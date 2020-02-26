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

public class HostsCondition implements ClientPolicyCondition {

    private static final Logger logger = Logger.getLogger(HostsCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public HostsCondition(KeycloakSession session, ComponentModel componentModel) {
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
        return isHostMatched();
    };

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public boolean isSatisfiedOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client) {
        ClientPolicyLogger.log(logger, "Dynamic Registration Endpoint - updating client");
        return isHostMatched();
    };

    // on Admin REST API Registration access for creating client
    @Override
    public boolean isSatisfiedOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for creating client");
        return isHostMatched();
    };

    // on Admin REST API Registration access for updating client
    @Override
    public boolean isSatisfiedOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for updating client");
        return isHostMatched();
    };

    private boolean isHostMatched() {
        String host = session.getContext().getRequestHeaders().getHeaderString("Host");

        ClientPolicyLogger.log(logger, "host = " + host);
        componentModel.getConfig().get(HostsConditionFactory.HOSTS).stream().forEach(i -> ClientPolicyLogger.log(logger, "host expected = " + i));

        boolean isMatched = componentModel.getConfig().get(HostsConditionFactory.HOSTS).stream().anyMatch(i -> i.equals(host));
        if(isMatched) {
            ClientPolicyLogger.log(logger, "host matched.");
        } else {
            ClientPolicyLogger.log(logger, "host unmatched.");
        }
        return isMatched;
    }

}
