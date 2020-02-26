package org.keycloak.services.clientpolicy.condition.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionFactory;

public class ClientAccessTypeConditionFactory implements ClientPolicyConditionFactory {

    public static final String PROVIDER_ID = "client-accesstype-condition";
    public static final String TYPE = "type";
    public static final String TYPE_CONFIDENTIAL = "confidential";
    public static final String TYPE_PUBLIC = "public";
    public static final String TYPE_BEARERONLY = "bearer-only";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty(TYPE, "client-accesstype.label", "client-accesstype.tooltip", ProviderConfigProperty.MULTIVALUED_LIST_TYPE, TYPE_CONFIDENTIAL);
        List<String> updateProfileValues = Arrays.asList(TYPE_CONFIDENTIAL, TYPE_PUBLIC, TYPE_BEARERONLY);
        property.setOptions(updateProfileValues);
        configProperties.add(property);
    }

    @Override
    public ClientPolicyCondition create(KeycloakSession session, ComponentModel model) {
        return new ClientAccessTypeCondition(session, model);
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
        return configProperties;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(KeycloakSession session) {
        return configProperties;
    }
}
