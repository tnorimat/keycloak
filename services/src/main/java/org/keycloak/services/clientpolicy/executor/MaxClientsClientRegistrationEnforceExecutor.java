package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;

public class MaxClientsClientRegistrationEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(MaxClientsClientRegistrationEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public MaxClientsClientRegistrationEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case REGISTER:
                RealmModel realm = session.getContext().getRealm();
                int currentCount = realm.getClients().size();
                int maxCount = componentModel.get(MaxClientsClientRegistrationEnforceExecutorFactory.MAX_CLIENTS, MaxClientsClientRegistrationEnforceExecutorFactory.DEFAULT_MAX_CLIENTS);

                if (currentCount >= maxCount) {
                    ClientPolicyLogger.log(logger, "Amount of clients is more then " + maxCount + ".");
                    throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Amount of clients is more then " + maxCount + ".");
                }
                break;
            default:
                return;
        }
    }
}
