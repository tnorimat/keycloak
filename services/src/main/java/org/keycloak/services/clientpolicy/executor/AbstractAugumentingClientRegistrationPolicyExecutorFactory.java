package org.keycloak.services.clientpolicy.executor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

public abstract class AbstractAugumentingClientRegistrationPolicyExecutorFactory implements ClientPolicyExecutorProviderFactory  {

    protected static final String IS_AUGMENT = "is-augment";

    private static final ProviderConfigProperty IS_AUGMENT_PROPERTY = new ProviderConfigProperty(
            IS_AUGMENT, null, null, ProviderConfigProperty.BOOLEAN_TYPE, false);

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<>(Arrays.asList(IS_AUGMENT_PROPERTY));
    }

}
