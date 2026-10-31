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

import java.util.stream.Stream;

import org.keycloak.models.CibaConfig;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.conformance.runner.BrowserInteraction;
import org.keycloak.testframework.conformance.runner.ConformanceModuleVariant;
import org.keycloak.testframework.conformance.runner.ConformanceResult;
import org.keycloak.testframework.realm.ManagedRealm;

/**
 * The FAPI-CIBA modules in the ping mode, where Keycloak notifies the suite's client notification endpoint. The
 * authentication device delays the approval past Keycloak's polling interval, see {@link #callbackDelay()}.
 */
@KeycloakIntegrationTest(config = FapiCibaServerConfig.class)
public class FapiCibaPingTest extends AbstractFapiCibaConformanceTest {

    @InjectRealm(config = FapiCibaPingRealmConfig.class)
    ManagedRealm realm;

    @Override
    protected String cibaMode() {
        return CibaConfig.CIBA_PING_MODE;
    }

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        return Stream.of(rejectingModules(), tokenModules(), userRejectsModules(), resourceModules(), rs256Modules(),
                // How Keycloak treats the responses of the client notification endpoint. The modules call the
                // resource endpoint, so they fail on the known Keycloak gaps only.
                modules(ConformanceResult.FAILED, BrowserInteraction.NONE,
                        "fapi-ciba-id1-ping-backchannel-notification-endpoint-response-has-body",
                        "fapi-ciba-id1-ping-backchannel-notification-endpoint-response-401",
                        "fapi-ciba-id1-ping-backchannel-notification-endpoint-response-403",
                        "fapi-ciba-id1-ping-with-mtls-ciba-notification-endpoint-response-401-and-require-server-does-not-retry",
                        "fapi-ciba-id1-ping-backchannel-notification-endpoint-return-redirect-request"))
                .flatMap(group -> group);
    }
}
