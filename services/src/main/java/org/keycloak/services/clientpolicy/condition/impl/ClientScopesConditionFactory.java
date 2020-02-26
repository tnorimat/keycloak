package org.keycloak.services.clientpolicy.condition.impl;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionFactory;

public class ClientScopesConditionFactory implements ClientPolicyConditionFactory {

    public static final String PROVIDER_ID = "clientscopes-condition";
    public static final String SCOPES = "scopes";
    public static final String TYPE = "type";
    public static final String DEFAULT = "Default";
    public static final String OPTIONAL = "Optional";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty(SCOPES, PROVIDER_ID + ".label", PROVIDER_ID + ".tooltip", ProviderConfigProperty.MULTIVALUED_STRING_TYPE, "offline_access");
        configProperties.add(property);
        property = new ProviderConfigProperty(TYPE, "Scope Type", "Default or Optional", ProviderConfigProperty.LIST_TYPE, OPTIONAL);
        configProperties.add(property);
    }

    @Override
    public ClientPolicyCondition create(KeycloakSession session, ComponentModel model) {
        return new ClientScopesCondition(session, model);

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
