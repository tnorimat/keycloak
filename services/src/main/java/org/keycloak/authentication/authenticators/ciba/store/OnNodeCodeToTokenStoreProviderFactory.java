package org.keycloak.authentication.authenticators.ciba.store;

import org.keycloak.Config;
import org.keycloak.models.CodeToTokenStoreProvider;
import org.keycloak.models.CodeToTokenStoreProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class OnNodeCodeToTokenStoreProviderFactory implements CodeToTokenStoreProviderFactory {

    public static final String PROVIDER_ID = "on-node-code-to-token-infinispan";

    private static final ConcurrentHashMap<UUID, OnNodeCodeValueEntity> storages = new ConcurrentHashMap<>();

    @Override
    public CodeToTokenStoreProvider create(KeycloakSession session) {
        return new OnNodeCodeToTokenStoreProvider(session, storages);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
