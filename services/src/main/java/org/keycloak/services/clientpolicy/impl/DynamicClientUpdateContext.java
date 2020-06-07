package org.keycloak.services.clientpolicy.impl;

import org.keycloak.models.ClientModel;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class DynamicClientUpdateContext implements ClientUpdateContext {

    private final ClientRegistrationContext context;
    private final RegistrationAuth authType;
    private final ClientModel client;

    public DynamicClientUpdateContext(ClientRegistrationContext context,
            RegistrationAuth authType, ClientModel client) {
        this.context = context;
        this.authType = authType;
        this.client = client;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.DYNAMIC_UPDATE;
    }

    @Override
    public ClientRegistrationContext getDynamicClientRegistrationContext() {
        return context;
    }

    @Override
    public RegistrationAuth getDynamicRegistrationAuth() {
        return authType;
    }

    @Override
    public ClientModel getCurrentClientModel() {
        return client;
    }

}
