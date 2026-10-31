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

package org.keycloak.tests.conformance.fapi2sign;

import java.util.stream.Stream;

import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.conformance.runner.BrowserInteraction;
import org.keycloak.testframework.conformance.runner.ConformanceModuleVariant;
import org.keycloak.testframework.conformance.runner.ConformanceResult;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.tests.conformance.ConformanceServerConfig;
import org.keycloak.tests.conformance.fapi2sign.configs.Fapi2MessageSigningRealmConfig;

import org.junit.jupiter.api.Disabled;

// TODO: enable once Keycloak rejects the request properly. When client2 presents a request_uri pushed by client1
//  with a signed request object, the secure-par-content executor verifies the request object with client2's keys,
//  and the resulting RuntimeException ("Failed to verify signature on 'request' object") is not handled, so Keycloak
//  answers with an internal server error instead of its "Invalid Request" error page.
@Disabled("Keycloak answers a request_uri presented by a different client with an internal server error, see the TODO")
@KeycloakIntegrationTest(config = ConformanceServerConfig.class)
public class Fapi2MessageSigningRequestUriForDifferentClientTest extends AbstractFapi2MessageSigningTest {

    @InjectRealm(config = Fapi2MessageSigningRealmConfig.class)
    ManagedRealm realm;

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        return modules(ConformanceResult.REVIEW, BrowserInteraction.errorPage("Invalid Request"),
                "fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client");
    }
}
