package org.keycloak.services.clientpolicy;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;

public class DynamicClientRegisteredContext implements ClientUpdateContext {

    private final ClientModel registeredClient;
    private JsonWebToken token;
    private ClientModel client;

    public DynamicClientRegisteredContext(ClientModel registeredClient,
                                          JsonWebToken token, RealmModel realm) {
        this.registeredClient = registeredClient;
        this.token = token;
        if (token != null && token.getIssuedFor() != null) {
            this.client = realm.getClientByClientId(token.getIssuedFor());
        }
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.REGISTERED;
    }

    @Override
    public ClientModel getRegisteredClient() {
        return registeredClient;
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
