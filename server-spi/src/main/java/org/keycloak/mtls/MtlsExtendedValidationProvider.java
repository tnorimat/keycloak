package org.keycloak.mtls;

import org.keycloak.provider.Provider;

import java.security.cert.X509Certificate;
import java.util.Map;

public interface MtlsExtendedValidationProvider extends Provider {

    Map<String, String> parseAdditionalFields(X509Certificate[] certs);

    void performAdditionalValidation(X509Certificate[] certs) throws MtlsValidationException;
}
