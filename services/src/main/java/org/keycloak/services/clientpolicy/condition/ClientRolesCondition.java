package org.keycloak.services.clientpolicy.condition;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.ClientPolicyVote;

public class ClientRolesCondition implements ClientPolicyConditionProvider {
    private static final Logger logger = Logger.getLogger(ClientRolesCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientRolesCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public ClientPolicyVote applyPolicy(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case AUTHORIZATION_REQUEST:
            case TOKEN_REQUEST:
            case TOKEN_REFRESH:
            case TOKEN_REVOKE:
            case TOKEN_INTROSPECT:
            case USERINFO_REQUEST:
            case LOGOUT_REQUEST:
                if (isRolesMatched(session.getContext().getClient())) return ClientPolicyVote.YES;
                return ClientPolicyVote.NO;
            default:
                return ClientPolicyVote.ABSTAIN;
        }
    }

    private boolean isRolesMatched(ClientModel client) {
        if (client == null) return false;

        List<String> rolesForMatching = getRolesForMatching();
        if (rolesForMatching == null) return false;

        client.getRoles().stream().forEach(i -> ClientPolicyLogger.log(logger, "client role = " + i.getName()));
        rolesForMatching.stream().forEach(i -> ClientPolicyLogger.log(logger, "roles expected = " + i));

        boolean isMatched = rolesForMatching.stream().anyMatch(i->client.getRoles().stream().anyMatch(j->j.getName().equals(i)));
        if (isMatched) {
            ClientPolicyLogger.log(logger, "role matched.");
        } else {
            ClientPolicyLogger.log(logger, "role unmatched.");
        }
        return isMatched;
    }

    private List<String> getRolesForMatching() {
        return componentModel.getConfig().get(ClientRolesConditionFactory.ROLES);
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
