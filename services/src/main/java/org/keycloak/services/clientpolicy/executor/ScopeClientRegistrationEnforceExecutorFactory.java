package org.keycloak.services.clientpolicy.executor;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class ScopeClientRegistrationEnforceExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "scope-client-reg-enforce-executor";

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session, ComponentModel model) {
        return new ScopeClientRegistrationEnforceExecutor(session, model);
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

    @Override
    public String getHelpText() {
        return "When present, then newly registered client won't have full scope allowed";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }
}
