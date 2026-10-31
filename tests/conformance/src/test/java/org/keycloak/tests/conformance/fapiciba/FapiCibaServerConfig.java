/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.tests.conformance.fapiciba;

import java.util.List;

import org.keycloak.testframework.conformance.KeycloakProxy;
import org.keycloak.testframework.conformance.ciba.CibaAuthenticationDevice;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.tests.conformance.ConformanceServerConfig;

/**
 * The FAPI-CIBA server configuration: TLS client authentication for the certificate bound access tokens, trusting the
 * CAs of the client certificates, and the {@link CibaAuthenticationDevice} as the CIBA HTTP authentication channel.
 * With the {@link KeycloakProxy}, the proxy terminates the client's TLS connection, so Keycloak reads the client
 * certificate from the header the proxy forwards and verifies it against its truststore.
 */
public class FapiCibaServerConfig extends ConformanceServerConfig {

    @Override
    public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
        config = super.configure(config)
                .option("https-client-auth", "request")
                .spiOption("ciba-auth-channel", "ciba-http-auth-channel", "http-authentication-channel-uri",
                        CibaAuthenticationDevice.instance().authenticationChannelUri());
        if (KeycloakProxy.enabled()) {
            config = config.option("spi-x509cert-lookup--provider", "nginx")
                    .spiOption("x509cert-lookup", "nginx", "ssl-client-cert", KeycloakProxy.CLIENT_CERTIFICATE_HEADER)
                    .spiOption("x509cert-lookup", "nginx", "trust-proxy-verification", "false");
        }
        return config;
    }

    @Override
    protected List<String> additionalTrustedCertificates() {
        return List.of(FapiCibaClientKey.CLIENT.caCertificatePem(), FapiCibaClientKey.CLIENT2.caCertificatePem());
    }
}
