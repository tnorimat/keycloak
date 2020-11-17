package org.keycloak.authentication.authenticators.ciba.store;

import org.keycloak.models.CodeToTokenStoreProvider;
import org.keycloak.models.KeycloakSession;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentMap;

public class OnNodeCodeToTokenStoreProvider implements CodeToTokenStoreProvider {

    private final KeycloakSession session;
    private final ConcurrentMap<UUID, OnNodeCodeValueEntity> codeCache;

    public OnNodeCodeToTokenStoreProvider(KeycloakSession session,
                                          ConcurrentMap<UUID, OnNodeCodeValueEntity> codeCache) {
        this.session = session;
        this.codeCache = codeCache;
    }

    @Override
    public void put(UUID codeId, int lifespanSeconds, Map<String, String> codeData) {
        OnNodeCodeValueEntity codeValue = new OnNodeCodeValueEntity(codeData);
        codeCache.put(codeId, codeValue);
    }

    @Override
    public Map<String, String> remove(UUID codeId) {
        OnNodeCodeValueEntity existing = codeCache.remove(codeId);
        return existing == null ? null : existing.getNotes();
    }

    @Override
    public Map<String, String> get(UUID codeId) {
        OnNodeCodeValueEntity existing = codeCache.get(codeId);
        return existing == null ? null : existing.getNotes();
    }

    @Override
    public void close() {

    }
}
