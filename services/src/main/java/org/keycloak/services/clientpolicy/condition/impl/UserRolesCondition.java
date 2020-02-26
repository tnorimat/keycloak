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

public class UserRolesCondition implements ClientPolicyCondition {

    private static final Logger logger = Logger.getLogger(UserRolesCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public UserRolesCondition(KeycloakSession session, ComponentModel componentModel) {
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
        return isRolesMatched(admin);
    };

    // on Admin REST API Registration access for updating client
    @Override
    public boolean isSatisfiedOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) {
        ClientPolicyLogger.log(logger, "Admin REST API Registration access for updating client");
        return isRolesMatched(admin);
    };

    private boolean isRolesMatched(AdminAuth admin) {
        if (admin.getUser() == null) return false;

        admin.getUser().getRoleMappings().stream().forEach(i -> ClientPolicyLogger.log(logger, " user role = " + i.getName()));
        componentModel.getConfig().get(UserRolesConditionFactory.ROLES).stream().forEach(i -> ClientPolicyLogger.log(logger, "roles expected = " + i));

        boolean isMatched = componentModel.getConfig().get(UserRolesConditionFactory.ROLES).stream().anyMatch(i->{
            return admin.getUser().getRoleMappings().stream().anyMatch(j->j.getName().equals(i));
            });
        if (isMatched) {
            ClientPolicyLogger.log(logger, "role matched.");
        } else {
            ClientPolicyLogger.log(logger, "role unmatched.");
        }
        return isMatched;
    }

}
