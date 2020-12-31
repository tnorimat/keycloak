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

public class TrustedHostClientEnforceExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "trusted-hosts-enforce-executor";

    public static final String TRUSTED_HOSTS = "trusted-hosts";
    public static final String HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH = "host-sending-registration-request-must-match";
    public static final String CLIENT_URIS_MUST_MATCH = "client-uris-must-match";

    private static final ProviderConfigProperty TRUSTED_HOSTS_PROPERTY = new ProviderConfigProperty();
    private static final ProviderConfigProperty HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY = new ProviderConfigProperty();
    private static final ProviderConfigProperty CLIENT_URIS_MUST_MATCH_PROPERTY = new ProviderConfigProperty();

    private static List<ProviderConfigProperty> configProperties = new LinkedList<>();

    static {
        TRUSTED_HOSTS_PROPERTY.setName(TRUSTED_HOSTS);
        TRUSTED_HOSTS_PROPERTY.setLabel("trusted-hosts.label");
        TRUSTED_HOSTS_PROPERTY.setHelpText("trusted-hosts.tooltip");
        TRUSTED_HOSTS_PROPERTY.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        TRUSTED_HOSTS_PROPERTY.setDefaultValue(null);
        configProperties.add(TRUSTED_HOSTS_PROPERTY);

        HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY.setName(HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH);
        HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY.setLabel("host-sending-registration-request-must-match.label");
        HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY.setHelpText("host-sending-registration-request-must-match.tooltip");
        HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY.setDefaultValue("true");
        configProperties.add(HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY);

        CLIENT_URIS_MUST_MATCH_PROPERTY.setName(CLIENT_URIS_MUST_MATCH);
        CLIENT_URIS_MUST_MATCH_PROPERTY.setLabel("client-uris-must-match.label");
        CLIENT_URIS_MUST_MATCH_PROPERTY.setHelpText("client-uris-must-match.tooltip");
        CLIENT_URIS_MUST_MATCH_PROPERTY.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CLIENT_URIS_MUST_MATCH_PROPERTY.setDefaultValue("true");
        configProperties.add(CLIENT_URIS_MUST_MATCH_PROPERTY);
    }

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session, ComponentModel model) {
        return new TrustedHostClientEnforceExecutor(session, model);
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
        return "Allows to specify from which hosts is user able to register and which redirect URIs can client use in it's configuration";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        ConfigurationValidationHelper.check(config)
                .checkBoolean(HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH_PROPERTY, true)
                .checkBoolean(CLIENT_URIS_MUST_MATCH_PROPERTY, true);

        TrustedHostClientEnforceExecutor policy = new TrustedHostClientEnforceExecutor(session, config);
        if (!policy.isHostMustMatch() && !policy.isClientUrisMustMatch()) {
            throw new ComponentValidationException("At least one of hosts verification or client URIs validation must be enabled");
        }
    }
}
