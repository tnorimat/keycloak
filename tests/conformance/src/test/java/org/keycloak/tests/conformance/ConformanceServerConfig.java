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

package org.keycloak.tests.conformance;

import org.keycloak.common.Profile;
import org.keycloak.testframework.conformance.ConformanceTls;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;

/**
 * Keycloak server configuration for the OpenID Connect conformance tests, meant to be shared with the other OpenID
 * provider conformance tests so the server is not restarted between them. It applies the BCP195 TLS restriction FAPI
 * requires, which does not affect the OpenID Connect plans, and deploys the script based protocol mappers of this module
 * (src/main/resources), which keep the ID tokens of the conformance realms free of claims the suite warns about, e.g.
 * Keycloak's typ claim.
 */
public class ConformanceServerConfig implements KeycloakServerConfig {

    @Override
    public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
        return config.features(Profile.Feature.SCRIPTS)
                .dependencyCurrentProject()
                .option("https-protocols", ConformanceTls.PROTOCOLS)
                .option("https-cipher-suites", ConformanceTls.BCP195_CIPHERS)
                .option("hostname", OpenIdConformanceServer.KEYCLOAK_BASE_URI.toString());
    }
}
