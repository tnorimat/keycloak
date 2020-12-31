package org.keycloak.services.clientpolicy;

public class DynamicClientViewContext implements ClientUpdateContext {

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.VIEW;
    }
}
