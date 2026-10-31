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

package org.keycloak.tests.conformance.fapi2;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.keycloak.testframework.conformance.KeycloakProxy;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.conformance.runner.BrowserInteraction;
import org.keycloak.testframework.conformance.runner.ConformanceModuleVariant;
import org.keycloak.testframework.conformance.runner.ConformanceResult;
import org.keycloak.tests.conformance.AbstractConformanceTest;

import com.fasterxml.jackson.databind.JsonNode;

import static org.keycloak.tests.conformance.KnownKeycloakGaps.MISSING_DATE_HEADER;

/**
 * Baseline for the FAPI 2.0 conformance tests. Keycloak is tested as an OpenID Connect provider authenticating clients
 * with private_key_jwt and sender constraining tokens with DPoP. Subclasses select the plan (Security Profile or
 * Message Signing) and the request method variant.
 *
 * The modules that call the resource endpoint (Keycloak's userinfo endpoint) are expected to fail, but only on the
 * known Keycloak gaps listed in {@link #knownFailures}, so that any other failure still fails the test. With the
 * {@link KeycloakProxy}, which adds the missing response headers, they are expected to pass except for those failing
 * on Keycloak's DPoP behaviour.
 */
public abstract class AbstractFapi2ConformanceTest extends AbstractConformanceTest {

    public static final String FAPI2_SECURITY_PROFILE_PLAN = "fapi2-security-profile-final-test-plan";
    public static final String FAPI2_MESSAGE_SIGNING_PLAN = "fapi2-message-signing-final-test-plan";

    // TODO: Keycloak's userinfo endpoint accepts a DPoP proof signed with RS256, which FAPI 2.0 does not permit, so
    //  the dpop-negative-tests module gets a 200 response where it expects 400 or 401.
    protected static final String DPOP_PROOF_WITH_RS256_ACCEPTED = "EnsureHttpStatusCodeIs400or401";

    private static final String DPOP_NEGATIVE_TESTS = "fapi2-security-profile-final-dpop-negative-tests";

    // What modules expected to fail on the missing Date header finish with when the KeycloakProxy adds it, if not PASSED
    private static final Map<String, ConformanceResult> RESULTS_WITHOUT_KNOWN_FAILURES = Map.of(
            // Keycloak renders its error page on the second authorization, which the suite snapshots for review
            "fapi2-security-profile-final-par-attempt-reuse-request_uri", ConformanceResult.REVIEW);

    protected abstract String plan();

    protected Map<String, String> planVariant() {
        return Map.of(
                "fapi_profile", "plain_fapi",
                "client_auth_type", "private_key_jwt",
                "sender_constrain", "dpop",
                "openid", "openid_connect");
    }

    /**
     * Discovers the variant combinations of the named modules, which share the expected result and browser
     * interaction. Test classes concatenate several groups when the modules need different interactions.
     */
    protected Stream<ConformanceModuleVariant> modules(ConformanceResult expectedResult,
            BrowserInteraction browserInteraction, String... names) {
        return discoverModuleVariants(plan(), planVariant(), List.of(names), expectedResult, browserInteraction);
    }

    // The KeycloakProxy adds the Date header, so with it only Keycloak's own DPoP behaviour remains a known failure
    @Override
    protected Set<String> knownFailures(ConformanceModuleVariant module) {
        Set<String> knownFailures = new HashSet<>();
        if (!KeycloakProxy.enabled()) {
            knownFailures.add(MISSING_DATE_HEADER);
        }
        if (DPOP_NEGATIVE_TESTS.equals(module.name())) {
            knownFailures.add(DPOP_PROOF_WITH_RS256_ACCEPTED);
        }
        return knownFailures;
    }

    @Override
    protected ConformanceResult resultWithoutKnownFailures(ConformanceModuleVariant module) {
        return RESULTS_WITHOUT_KNOWN_FAILURES.getOrDefault(module.name(), ConformanceResult.PASSED);
    }

    @Override
    protected JsonNode suiteConfig(ConformanceModuleVariant module) {
        return Fapi2SuiteConfig.create(OpenIdConformanceServer.keycloakBaseUri(), module.browserInteraction()).toJson();
    }
}
