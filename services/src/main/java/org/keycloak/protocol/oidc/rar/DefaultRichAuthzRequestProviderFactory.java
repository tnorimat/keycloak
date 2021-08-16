package org.keycloak.protocol.oidc.rar;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class DefaultRichAuthzRequestProviderFactory implements RichAuthzRequestProviderFactory {

    public static final String PROVIDER_ID = "default-rich-authz-request-processor";

    @Override
    public RichAuthzRequestProvider create(KeycloakSession session) {
        return new DefaultRichAuthzRequestProvider();
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
