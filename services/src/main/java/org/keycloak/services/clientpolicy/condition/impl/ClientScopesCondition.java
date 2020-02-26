package org.keycloak.services.clientpolicy.condition.impl;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.resources.admin.AdminAuth;

public class ClientScopesCondition implements ClientPolicyCondition {
    private static final Logger logger = Logger.getLogger(ClientScopesCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientScopesCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public boolean isEvaluatedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.ADMIN_REGISTER:
            case ClientPolicyEvent.ADMIN_UPDATE:
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
        return isScopeMatched(admin);
    };

    // on Admin REST API Registration access for updating client
    @Override
    public boolean isSatisfiedOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for updating client");
        return isScopeMatched(admin);
    };


    private boolean isScopeMatched(AdminAuth admin) {
        if (admin.getUser() == null) return false;

        admin.getClient().getClientScopes(true, true).keySet().stream().forEach(i -> ClientPolicyLogger.log(logger, " default client scope = " + i));
        admin.getClient().getClientScopes(false, true).keySet().stream().forEach(i -> ClientPolicyLogger.log(logger, " optional client scope = " + i));
        componentModel.getConfig().get(ClientScopesConditionFactory.SCOPES).stream().forEach(i -> ClientPolicyLogger.log(logger, "scope expected = " + i));

        boolean isDefaultScope = ClientScopesConditionFactory.DEFAULT.equals(componentModel.getConfig().getFirst(ClientScopesConditionFactory.TYPE));
        boolean isMatched = componentModel.getConfig().get(ClientScopesConditionFactory.SCOPES).stream().anyMatch(i->{
                return admin.getClient().getClientScopes(isDefaultScope, true).keySet().stream().anyMatch(j->j.equals(i));
                });
        if (isMatched) {
            ClientPolicyLogger.log(logger, "scope matched.");
        } else {
            ClientPolicyLogger.log(logger, "scope unmatched.");
        }
        return isMatched;
    }

}
