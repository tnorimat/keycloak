package org.keycloak.protocol.oidc.rar;

import org.keycloak.common.Profile;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderFactory;

public interface RichAuthzRequestProviderFactory extends ProviderFactory<RichAuthzRequestProvider>,
        EnvironmentDependentProviderFactory {

    @Override
    default boolean isSupported() {
        return Profile.isFeatureEnabled(Profile.Feature.RAR);
    }
}
