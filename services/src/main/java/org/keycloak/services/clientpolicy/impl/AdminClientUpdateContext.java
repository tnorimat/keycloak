package org.keycloak.services.clientpolicy.impl;

import org.keycloak.models.ClientModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.resources.admin.AdminAuth;

public class AdminClientUpdateContext implements ClientUpdateContext {

    private final ClientRepresentation clientRepresentation;
    private final AdminAuth adminAuth;
    private final ClientModel client;

    public AdminClientUpdateContext(ClientRepresentation clientRepresentation,
            AdminAuth adminAuth, ClientModel client) {
        this.clientRepresentation = clientRepresentation;
        this.adminAuth = adminAuth;
        this.client = client;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.ADMIN_UPDATE;
    }

    @Override
    public ClientRepresentation getProposedClientRepresentation() {
        return clientRepresentation;
    }

    @Override
    public AdminAuth getAdminAuth() {
        return adminAuth;
    }

    @Override
    public ClientModel getCurrentClientModel() {
        return client;
    }

}
