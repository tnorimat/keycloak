package org.keycloak.services.clientpolicy;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;

public class DynamicClientUpdatedContext implements ClientUpdateContext {

    private final ClientModel clientUpdated;
    private final JsonWebToken token;
    private ClientModel client;

    public DynamicClientUpdatedContext(ClientModel clientUpdated, JsonWebToken token, RealmModel realm) {
        this.clientUpdated = clientUpdated;
        this.token = token;
        if (token != null && token.getIssuedFor() != null) {
            this.client = realm.getClientByClientId(token.getIssuedFor());
        }
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.UPDATED;
    }

    @Override
    public ClientModel getClientUpdated() {
        return clientUpdated;
    }

    @Override
    public ClientModel getAuthenticatedClient() {
        return client;
    }

    @Override
    public JsonWebToken getToken() {
        return token;
    }
}
