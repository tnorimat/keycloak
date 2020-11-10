package org.keycloak.authentication.authenticators.ciba.store;

import org.infinispan.client.hotrod.exceptions.HotRodClientException;
import org.infinispan.commons.api.BasicCache;
import org.jboss.logging.Logger;
import org.keycloak.models.CodeToTokenStoreProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.sessions.infinispan.entities.ActionTokenValueEntity;

import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

public class OnNodeCodeToTokenStoreProvider implements CodeToTokenStoreProvider {

    private static final Logger logger = Logger.getLogger(OnNodeCodeToTokenStoreProvider.class);

    private final KeycloakSession session;
    private final Supplier<BasicCache<UUID, ActionTokenValueEntity>> codeCache;

    public OnNodeCodeToTokenStoreProvider(KeycloakSession session,
                                          Supplier<BasicCache<UUID, ActionTokenValueEntity>> codeCache) {
        this.session = session;
        this.codeCache = codeCache;
    }

    @Override
    public void put(UUID codeId, int lifespanSeconds, Map<String, String> codeData) {

    }

    @Override
    public Map<String, String> remove(UUID codeId) {
        return null;
    }

    @Override
    public Map<String, String> get(UUID codeId) {
        return null;
    }

    @Override
    public void close() {

    }
}
