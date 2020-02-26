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
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class AuthnMethodsConditionFactory implements ClientPolicyConditionFactory {

    public static final String PROVIDER_ID = "authnmethods-condition";
    public static final String AUTH_METHOD = "auth-method";
    public static final String BY_ADMIN_REST_API = "ByAdminRestAPI";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty(AUTH_METHOD, PROVIDER_ID + ".label", PROVIDER_ID + ".tooltip", ProviderConfigProperty.MULTIVALUED_LIST_TYPE, RegistrationAuth.AUTHENTICATED.name());
        List<String> updateProfileValues = Arrays.asList(RegistrationAuth.ANONYMOUS.name(), RegistrationAuth.AUTHENTICATED.name(), BY_ADMIN_REST_API);
        property.setOptions(updateProfileValues);
        configProperties.add(property);
    }

    @Override
    public ClientPolicyCondition create(KeycloakSession session, ComponentModel model) {
        return new AuthnMethodsCondition(session, model);
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
