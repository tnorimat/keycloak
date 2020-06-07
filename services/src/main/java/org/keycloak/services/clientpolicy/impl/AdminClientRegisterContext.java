package org.keycloak.services.clientpolicy.impl;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.resources.admin.AdminAuth;

public class AdminClientRegisterContext implements ClientUpdateContext {

    private final ClientRepresentation clientRepresentation;
    private final AdminAuth adminAuth;

    public AdminClientRegisterContext(ClientRepresentation clientRepresentation,
            AdminAuth adminAuth) {
        this.clientRepresentation = clientRepresentation;
        this.adminAuth = adminAuth;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.ADMIN_REGISTER;
    }

    @Override
    public ClientRepresentation getProposedClientRepresentation() {
        return clientRepresentation;
    }

    @Override
    public AdminAuth getAdminAuth() {
        return adminAuth;
    }

}
