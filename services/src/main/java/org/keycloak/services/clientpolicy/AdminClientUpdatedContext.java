package org.keycloak.services.clientpolicy;

import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.resources.admin.AdminAuth;

public class AdminClientUpdatedContext implements ClientUpdateContext {

    private final ClientRepresentation clientRepresentation;
    private final AdminAuth adminAuth;
    private final ClientModel client;

    public AdminClientUpdatedContext(ClientRepresentation clientRepresentation,
                                     AdminAuth adminAuth, ClientModel client) {
        this.clientRepresentation = clientRepresentation;
        this.adminAuth = adminAuth;
        this.client = client;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.UPDATED;
    }

    @Override
    public ClientRepresentation getProposedClientRepresentation() {
        return clientRepresentation;
    }

    @Override
    public ClientModel getAuthenticatedClient() {
        return client;
    }

    @Override
    public UserModel getAuthenticatedUser() {
        return adminAuth.getUser();
    }

    @Override
    public JsonWebToken getToken() {
        return adminAuth.getToken();
    }
}
