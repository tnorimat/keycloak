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

public class UsersCondition implements ClientPolicyCondition {

    private static final Logger logger = Logger.getLogger(UsersCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public UsersCondition(KeycloakSession session, ComponentModel componentModel) {
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
        return isUsersMatched(admin);
    };

    // on Admin REST API Registration access for updating client
    @Override
    public boolean isSatisfiedOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for updating client");
        return isUsersMatched(admin);
    };

    private boolean isUsersMatched(AdminAuth admin) {
        if (admin.getUser() == null) return false;
        String username = admin.getUser().getUsername();

        ClientPolicyLogger.log(logger, "user name = " + username);
        componentModel.getConfig().get(UsersConditionFactory.USERS).stream().forEach(i -> ClientPolicyLogger.log(logger, "users expected = " + i));

        boolean isMatched = componentModel.getConfig().get(UsersConditionFactory.USERS).stream().anyMatch(i->{
            return i.equals(username);
            });
        if (isMatched) {
            ClientPolicyLogger.log(logger, "user matched.");
        } else {
            ClientPolicyLogger.log(logger, "user unmatched.");
        }
        return isMatched;
    }

}
