package org.keycloak.services.clientpolicy.executor.impl;

import java.util.Collections;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorFactory;

public class SecureClientAuthenticationExecutorFactory implements ClientPolicyExecutorFactory {

    public static final String PROVIDER_ID = "secure-clientauthn-executor";

    @Override
    public ClientPolicyExecutor create(KeycloakSession session, ComponentModel model) {
        return new SecureClientAuthenticationExecutor(session, model);
    }

    @Override
    public void init(Scope config) {
        // TODO Auto-generated method stub

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // TODO Auto-generated method stub

    }

    @Override
    public void close() {
        // TODO Auto-generated method stub

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(KeycloakSession session) {
        return Collections.emptyList();
    }

}
