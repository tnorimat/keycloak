package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class ScopeClientRegistrationEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ScopeClientRegistrationEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ScopeClientRegistrationEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
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
                registeredClientContext.getRegisteredClient().setFullScopeAllowed(false);
                break;
            case UPDATE:
                ClientUpdateContext updateClientContext = (ClientUpdateContext) context;

                if (updateClientContext.getClientToBeUpdated() == null) {
                    return;
                }
                if (updateClientContext.getProposedClientRepresentation().isFullScopeAllowed() == null) {
                    return;
                }

                boolean fullScopeAllowed = updateClientContext.getClientToBeUpdated().isFullScopeAllowed();
                boolean newFullScopeAllowed = updateClientContext.getProposedClientRepresentation().isFullScopeAllowed();

                if (!fullScopeAllowed && newFullScopeAllowed) {
                    throw new ClientPolicyException(Errors.NOT_ALLOWED, "Not permitted to enable fullScopeAllowed");
                }
                break;
            default:
                return;
        }
    }
}
