package org.keycloak.services.clientpolicy.condition;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class ClientRolesConditionFactory implements ClientPolicyConditionProviderFactory {

    public static final String PROVIDER_ID = "clientroles-condition";
    public static final String ROLES = "roles";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty(ROLES, PROVIDER_ID + ".label", PROVIDER_ID + ".tooltip", ProviderConfigProperty.MULTIVALUED_STRING_TYPE, "view-profile");
        configProperties.add(property);
    }

    @Override
    public ClientPolicyConditionProvider create(KeycloakSession session, ComponentModel model) {
        return new ClientRolesCondition(session, model);

    }

    @Override
    public void init(Scope config) {
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
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

}
