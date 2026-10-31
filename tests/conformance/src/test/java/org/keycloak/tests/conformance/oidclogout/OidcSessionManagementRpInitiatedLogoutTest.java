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

package org.keycloak.tests.conformance.oidclogout;

import java.util.stream.Stream;

import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.conformance.runner.BrowserInteraction;
import org.keycloak.testframework.conformance.runner.ConformanceModuleVariant;
import org.keycloak.testframework.conformance.runner.ConformanceResult;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.tests.conformance.ConformanceServerConfig;

import org.junit.jupiter.api.Disabled;

// TODO: enable once the suite's browser can run Keycloak's check_session_iframe. The suite drives an HtmlUnit browser,
//  and Keycloak's iframe, an ES module script using async functions, fetch and Web Crypto, never answers the session
//  check there, so the module times out on its first session verification page, after the login and the session_state
//  checks have passed.
@Disabled("Keycloak's check_session_iframe does not answer in the suite's HtmlUnit browser, see the TODO")
@KeycloakIntegrationTest(config = ConformanceServerConfig.class)
public class OidcSessionManagementRpInitiatedLogoutTest extends AbstractOidcLogoutConformanceTest {

    @InjectRealm(config = OidcLogoutRealmConfig.class)
    ManagedRealm realm;

    @Override
    protected String plan() {
        return SESSION_MANAGEMENT_PLAN;
    }

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        // The suite checks the session state in its own pages before and after the logout
        return modules(ConformanceResult.PASSED, BrowserInteraction.SESSION_MANAGEMENT_LOGOUT,
                "oidcc-session-management-rp-initiated-logout");
    }
}
