package org.keycloak.authentication.authenticators.ciba.store;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.Flag;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.commons.api.BasicCache;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.CodeToTokenStoreProvider;
import org.keycloak.models.CodeToTokenStoreProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.sessions.infinispan.entities.ActionTokenValueEntity;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;

import java.util.UUID;
import java.util.function.Supplier;

public class OnNodeCodeToTokenStoreProviderFactory implements CodeToTokenStoreProviderFactory {

    private static final Logger logger = Logger.getLogger(OnNodeCodeToTokenStoreProviderFactory.class);

    public static final String PROVIDER_ID = "on-node-code-to-token-infinispan";

    @Override
    public CodeToTokenStoreProvider create(KeycloakSession session) {
        return new OnNodeCodeToTokenStoreProvider(session, null);
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
        return null;
    }

}
