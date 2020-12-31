package org.keycloak.services.clientpolicy;

public class AdminClientViewContext implements ClientUpdateContext {

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.VIEW;
    }
}
