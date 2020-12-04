package org.keycloak.services.clientpolicy.executor;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.LinkedList;
import java.util.List;

public class MaxClientsClientRegistrationEnforceExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "max-clients-enforce-executor";
    public static final String MAX_CLIENTS = "max-clients";
    public static final ProviderConfigProperty MAX_CLIENTS_PROPERTY = new ProviderConfigProperty();

    public static final int DEFAULT_MAX_CLIENTS = 200;

    private static List<ProviderConfigProperty> configProperties = new LinkedList<>();

    static {
        MAX_CLIENTS_PROPERTY.setName(MAX_CLIENTS);
        MAX_CLIENTS_PROPERTY.setLabel("max-clients.label");
        MAX_CLIENTS_PROPERTY.setHelpText("max-clients.tooltip");
        MAX_CLIENTS_PROPERTY.setType(ProviderConfigProperty.STRING_TYPE);
        MAX_CLIENTS_PROPERTY.setDefaultValue(String.valueOf(DEFAULT_MAX_CLIENTS));
        configProperties.add(MAX_CLIENTS_PROPERTY);
    }

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session, ComponentModel model) {
        return new MaxClientsClientRegistrationEnforceExecutor(session, model);
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
        return "It prohibits the client creation due to reach max count of clients";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
                .checkInt(MAX_CLIENTS_PROPERTY, true);
    }
}
