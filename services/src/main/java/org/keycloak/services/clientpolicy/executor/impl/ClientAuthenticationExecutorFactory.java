package org.keycloak.services.clientpolicy.executor.impl;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorFactory;

public class ClientAuthenticationExecutorFactory implements ClientPolicyExecutorFactory {

    public static final String PROVIDER_ID = "client-authn-executor";
    public static final String CLIENT_AUTHNS = "client-authns";
    private static final ProviderConfigProperty CLIENTAUTHNS_PROPERTY = new ProviderConfigProperty(CLIENT_AUTHNS, "client-authns.label", "client-authns.tooltip", ProviderConfigProperty.MULTIVALUED_STRING_TYPE, null);

    @Override
    public ClientPolicyExecutor create(KeycloakSession session, ComponentModel model) {
        return new ClientAuthenticationExecutor(session, model);
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
        return Arrays.asList(CLIENTAUTHNS_PROPERTY);

    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(KeycloakSession session) {
        return Arrays.asList(CLIENTAUTHNS_PROPERTY);
    }
}
