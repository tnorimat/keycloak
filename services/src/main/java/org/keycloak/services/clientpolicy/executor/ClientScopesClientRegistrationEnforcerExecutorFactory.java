package org.keycloak.services.clientpolicy.executor;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ClientScopesClientRegistrationEnforcerExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "client-scopes-enforce-executor";

    public static final String ALLOWED_CLIENT_SCOPES = "allowed-client-scopes";
    public static final String ALLOW_DEFAULT_SCOPES = "allow-default-scopes";

    private List<ProviderConfigProperty> configProperties;

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session, ComponentModel model) {
        return new ClientScopesClientRegistrationEnforcerExecutor(session, model);
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
        return "When present, it allows to specify whitelist of client scopes, which will be allowed in representation of registered (or updated) client";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return getConfigProperties(null);
    }

    public List<ProviderConfigProperty> getConfigProperties(KeycloakSession session) {
        List<ProviderConfigProperty> configProps = new LinkedList<>();

        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ALLOWED_CLIENT_SCOPES);
        property.setLabel("allowed-client-scopes.label");
        property.setHelpText("allowed-client-scopes.tooltip");
        property.setType(ProviderConfigProperty.MULTIVALUED_LIST_TYPE);

        if (session != null) {
            property.setOptions(getClientScopes(session));
        }
        configProps.add(property);

        property = new ProviderConfigProperty();
        property.setName(ALLOW_DEFAULT_SCOPES);
        property.setLabel("allow-default-scopes.label");
        property.setHelpText("allow-default-scopes.tooltip");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(true);
        configProps.add(property);

        configProperties = configProps;
        return configProperties;
    }

    private List<String> getClientScopes(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            return Collections.emptyList();
        } else {
            List<ClientScopeModel> clientScopes = realm.getClientScopes();

            return clientScopes.stream().map(ClientScopeModel::getName).collect(Collectors.toList());
        }
    }
}
