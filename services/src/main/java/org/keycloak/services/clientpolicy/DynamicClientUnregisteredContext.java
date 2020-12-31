package org.keycloak.services.clientpolicy;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

public class DynamicClientUnregisteredContext implements ClientUpdateContext {

    private JsonWebToken token;
    private UserModel user;
    private ClientModel client;

    public DynamicClientUnregisteredContext(KeycloakSession session,
                                            JsonWebToken token, RealmModel realm) {
        this.token = token;
        if (token != null) {
            if (token.getSubject() != null) {
                this.user = session.users().getUserById(token.getSubject(), realm);
            }
            if (token.getIssuedFor() != null) {
                this.client = realm.getClientByClientId(token.getIssuedFor());
            }
        }
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.UNREGISTER;
    }

    @Override
    public ClientModel getAuthenticatedClient() {
        return client;
    }

    @Override
    public UserModel getAuthenticatedUser() {
        return user;
    }

    @Override
    public JsonWebToken getToken() {
        return token;
    }
}
