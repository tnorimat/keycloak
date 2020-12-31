package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class ClientDisabledClientEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ClientDisabledClientEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientDisabledClientEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
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
            case REGISTERED:
                ClientUpdateContext registeredClientContext = (ClientUpdateContext) context;
                registeredClientContext.getRegisteredClient().setEnabled(false);
                break;
            case UPDATE:
                ClientUpdateContext updateClientContext = (ClientUpdateContext) context;
                if (updateClientContext.getProposedClientRepresentation().isEnabled() == null) {
                    return;
                }
                boolean isEnabled = updateClientContext.getClientToBeUpdated().isEnabled();
                boolean newEnabled = updateClientContext.getProposedClientRepresentation().isEnabled();

                if (!isEnabled && newEnabled) {
                    throw new ClientPolicyException(Errors.NOT_ALLOWED, "Not permitted to enable client");
                }
                break;
            default:
                return;
        }
    }
}
