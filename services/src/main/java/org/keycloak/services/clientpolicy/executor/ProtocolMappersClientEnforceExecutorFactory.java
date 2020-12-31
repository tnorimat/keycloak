package org.keycloak.services.clientpolicy.executor;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ProtocolMappersClientEnforceExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "protocol-mappers-enforce-executor";
    public static final String ALLOWED_PROTOCOL_MAPPER_TYPES = "allowed-protocol-mapper-types";

    private final List<ProviderConfigProperty> configProperties = new LinkedList<>();

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session, ComponentModel model) {
        return new ProtocolMappersClientEnforceExecutor(session, model);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ALLOWED_PROTOCOL_MAPPER_TYPES);
        property.setLabel("allowed-protocol-mappers.label");
        property.setHelpText("allowed-protocol-mappers.tooltip");
        property.setType(ProviderConfigProperty.MULTIVALUED_LIST_TYPE);
        property.setOptions(getProtocolMapperFactoryIds(factory));
        configProperties.add(property);
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
        return "When present, it allows to specify whitelist of protocol mapper types, which will be allowed in representation of registered (or updated) client";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    private List<String> getProtocolMapperFactoryIds(KeycloakSessionFactory sessionFactory) {
        List<ProviderFactory> protocolMapperFactories = sessionFactory.getProviderFactories(ProtocolMapper.class);
        return protocolMapperFactories.stream().map(ProviderFactory::getId).collect(Collectors.toList());
    }
}
