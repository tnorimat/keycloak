package org.keycloak.mtls;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class MtlsExtendedValidationSpi implements Spi {
    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "tls-client-extended-validation-impl";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return MtlsExtendedValidationProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return MtlsExtendedValidationProviderFactory.class;
    }
}
