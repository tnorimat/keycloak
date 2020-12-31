package org.keycloak.services.clientpolicy;

import org.keycloak.models.ClientModel;
import org.keycloak.services.resources.admin.AdminAuth;

public class AdminClientRegisteredContext implements ClientUpdateContext {

    private final ClientModel registeredClient;
    private final AdminAuth adminAuth;

    public AdminClientRegisteredContext(ClientModel registeredClient,
                                        AdminAuth adminAuth) {
        this.registeredClient = registeredClient;
        this.adminAuth = adminAuth;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.REGISTERED;
    }

    @Override
    public ClientModel getAuthenticatedClient() {
        return adminAuth.getClient();
    }

    @Override
    public ClientModel getRegisteredClient() {
        return registeredClient;
    }
}
