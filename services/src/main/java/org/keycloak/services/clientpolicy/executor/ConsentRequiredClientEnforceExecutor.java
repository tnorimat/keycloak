package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class ConsentRequiredClientEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ConsentRequiredClientEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ConsentRequiredClientEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
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
                registeredClientContext.getRegisteredClient().setConsentRequired(true);
                break;
            case UPDATE:
                ClientUpdateContext clientUpdateContext = (ClientUpdateContext) context;
                ClientUpdateContext updateClientContext = (ClientUpdateContext) context;

                if (updateClientContext.getProposedClientRepresentation().isConsentRequired() == null) {
                    return;
                }
                if (updateClientContext.getClientToBeUpdated() == null) {
                    return;
                }

                boolean consentRequired = clientUpdateContext.getClientToBeUpdated().isConsentRequired();
                boolean newConsentRequired = clientUpdateContext.getProposedClientRepresentation().isConsentRequired();

                if (consentRequired && !newConsentRequired) {
                    throw new ClientPolicyException(Errors.NOT_ALLOWED, "Not permitted to update consentRequired to false");
                }
                break;
            default:
                return;
        }
    }
}
