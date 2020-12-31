package org.keycloak.services.clientpolicy.executor;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class ConsentRequiredClientEnforceExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "consent-required-enforce-executor";

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session, ComponentModel model) {
        return new ConsentRequiredClientEnforceExecutor(session, model);
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
        return "When present, then newly registered client will always have 'consentRequired' switch enabled";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }
}
