package org.keycloak.services.clientpolicy.impl;

import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class DynamicClientRegisterContext implements ClientUpdateContext {

    private final ClientRegistrationContext context;
    private final RegistrationAuth authType;

    public DynamicClientRegisterContext(ClientRegistrationContext context,
            RegistrationAuth authType) {
        this.context = context;
        this.authType = authType;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.DYNAMIC_REGISTER;
    }

    @Override
    public ClientRegistrationContext getDynamicClientRegistrationContext() {
        return context;
    }

    @Override
    public RegistrationAuth getDynamicRegistrationAuth() {
        return authType;
    }

}
