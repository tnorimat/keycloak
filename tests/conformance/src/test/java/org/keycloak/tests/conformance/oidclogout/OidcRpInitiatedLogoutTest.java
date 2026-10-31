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

/**
 * The RP-Initiated Logout OP certification plan.
 */
@KeycloakIntegrationTest(config = ConformanceServerConfig.class)
public class OidcRpInitiatedLogoutTest extends AbstractOidcLogoutConformanceTest {

    @InjectRealm(config = OidcLogoutRealmConfig.class)
    ManagedRealm realm;

    @Override
    protected String plan() {
        return RP_INITIATED_LOGOUT_PLAN;
    }

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        return Stream.of(
                modules(ConformanceResult.PASSED, BrowserInteraction.NONE,
                        "oidcc-rp-initiated-logout-discovery-endpoint-verification"),
                // Keycloak redirects to the post_logout_redirect_uri, then prompt=none fails as the user is logged out
                modules(ConformanceResult.PASSED, BrowserInteraction.LOGOUT,
                        "oidcc-rp-initiated-logout",
                        "oidcc-rp-initiated-logout-no-state"),
                // Keycloak must not redirect back, but render its error page or ask the user to confirm the logout,
                // which the suite snapshots for review
                modules(ConformanceResult.REVIEW, BrowserInteraction.LOGOUT_PAGE_SCREENSHOT,
                        "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
                        "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
                        "oidcc-rp-initiated-logout-modified-id-token-hint",
                        "oidcc-rp-initiated-logout-bad-id-token-hint",
                        "oidcc-rp-initiated-logout-no-id-token-hint"),
                // Without a post_logout_redirect_uri Keycloak renders its logged out page, which the suite snapshots
                modules(ConformanceResult.REVIEW, BrowserInteraction.CONFIRM_LOGOUT_WITH_SCREENSHOT,
                        "oidcc-rp-initiated-logout-no-params",
                        "oidcc-rp-initiated-logout-no-post-logout-redirect-uri",
                        "oidcc-rp-initiated-logout-only-state"))
                .flatMap(group -> group);
    }
}
