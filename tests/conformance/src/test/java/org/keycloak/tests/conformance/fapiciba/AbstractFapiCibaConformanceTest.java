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

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.keycloak.models.CibaConfig;
import org.keycloak.testframework.conformance.KeycloakProxy;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.conformance.ciba.CibaAuthenticationDevice;
import org.keycloak.testframework.conformance.runner.BrowserInteraction;
import org.keycloak.testframework.conformance.runner.ConformanceModuleVariant;
import org.keycloak.testframework.conformance.runner.ConformanceResult;
import org.keycloak.tests.conformance.AbstractConformanceTest;

import com.fasterxml.jackson.databind.JsonNode;

import static org.keycloak.tests.conformance.KnownKeycloakGaps.MISSING_DATE_HEADER;

/**
 * Baseline for the FAPI-CIBA plan with statically registered clients authenticating with private_key_jwt. The
 * modules need no browser: the suite approves or denies the CIBA requests through the
 * {@link CibaAuthenticationDevice}. Subclasses select the token delivery mode and the module groups they run.
 *
 * The modules calling the resource endpoint (Keycloak's userinfo endpoint) are expected to fail, but only on the known
 * Keycloak gaps of resource endpoint responses: the missing Date and x-fapi-interaction-id headers. With the
 * {@link KeycloakProxy}, which adds them, these modules are expected to pass.
 */
public abstract class AbstractFapiCibaConformanceTest extends AbstractConformanceTest {

    public static final String FAPI_CIBA_PLAN = "fapi-ciba-id1-test-plan";

    // TODO: Keycloak's userinfo endpoint does not return the x-fapi-interaction-id header, which FAPI 1.0 requires
    //  resource servers to return.
    protected static final String MISSING_FAPI_INTERACTION_ID = "CheckForFAPIInteractionIdInResourceResponse";
    // follows from the missing header, as the suite compares the returned interaction id with the one it sent
    protected static final String FAPI_INTERACTION_ID_MISMATCH = "EnsureMatchingFAPIInteractionId";

    protected abstract String cibaMode();

    // How long the authentication device waits after the approval before it completes the request. In the ping mode
    // the suite polls the token endpoint just before it approves, and requests the tokens once the notification
    // arrives, so the delay must exceed Keycloak's polling interval or Keycloak answers that token request with
    // slow_down. The margin of 3 seconds absorbs corrections of the system clock, which shorten the interval Keycloak
    // measures.
    protected Duration callbackDelay() {
        return CibaConfig.CIBA_PING_MODE.equals(cibaMode())
                ? Duration.ofSeconds(CibaConfig.DEFAULT_CIBA_POLICY_INTERVAL + 3)
                : Duration.ZERO;
    }

    protected Map<String, String> planVariant() {
        return Map.of(
                "fapi_ciba_profile", "plain_fapi",
                "client_auth_type", "private_key_jwt",
                "ciba_mode", cibaMode(),
                "client_registration", "static_client");
    }

    /**
     * Discovers the variant combinations of the named modules, which share the expected result and browser
     * interaction.
     */
    protected Stream<ConformanceModuleVariant> modules(ConformanceResult expectedResult,
            BrowserInteraction browserInteraction, String... names) {
        return discoverModuleVariants(FAPI_CIBA_PLAN, planVariant(), List.of(names), expectedResult, browserInteraction);
    }

    // The KeycloakProxy adds both missing headers, so with it the modules are expected to pass
    @Override
    protected Set<String> knownFailures(ConformanceModuleVariant module) {
        return KeycloakProxy.enabled()
                ? Set.of()
                : Set.of(MISSING_DATE_HEADER, MISSING_FAPI_INTERACTION_ID, FAPI_INTERACTION_ID_MISMATCH);
    }

    // Modules rejecting the request before the user is involved, or not using it at all
    protected Stream<ConformanceModuleVariant> rejectingModules() {
        return modules(ConformanceResult.PASSED, BrowserInteraction.NONE,
                "fapi-ciba-id1-discovery-end-point-verification",
                "fapi-ciba-id1-auth-req-id-expired",
                "fapi-ciba-id1-ensure-request-object-missing-aud-fails",
                "fapi-ciba-id1-ensure-request-object-bad-aud-fails",
                "fapi-ciba-id1-ensure-request-object-missing-iss-fails",
                "fapi-ciba-id1-ensure-request-object-bad-iss-fails",
                "fapi-ciba-id1-ensure-request-object-missing-exp-fails",
                "fapi-ciba-id1-ensure-request-object-expired-exp-fails",
                "fapi-ciba-id1-ensure-request-object-exp-is-70-minutes-in-future-fails",
                "fapi-ciba-id1-ensure-request-object-missing-iat-fails",
                "fapi-ciba-id1-ensure-request-object-missing-nbf-fails",
                "fapi-ciba-id1-ensure-request-object-nbf-is-10-minutes-in-future-fails",
                "fapi-ciba-id1-ensure-request-object-nbf-is-70-minutes-in-past-fails",
                "fapi-ciba-id1-ensure-request-object-missing-jti-fails",
                "fapi-ciba-id1-ensure-request-object-signature-algorithm-is-none-fails",
                "fapi-ciba-id1-ensure-request-object-signature-algorithm-is-bad-fails",
                "fapi-ciba-id1-ensure-request-object-signed-by-other-client-fails",
                "fapi-ciba-id1-ensure-authorization-request-with-multiple-hints-fails",
                "fapi-ciba-id1-ensure-wrong-auth-req-id-in-token-endpoint-request",
                "fapi-ciba-id1-ensure-without-client-assertion-in-token-endpoint-request",
                "fapi-ciba-id1-ensure-without-client-assertion-in-backchannel-authorization-request",
                "fapi-ciba-id1-ensure-unsigned-backchannel-authorization-request-fails");
    }

    // Modules obtaining tokens without calling the resource endpoint
    protected Stream<ConformanceModuleVariant> tokenModules() {
        return modules(ConformanceResult.PASSED, BrowserInteraction.NONE,
                "fapi-ciba-id1-multiple-call-to-token-endpoint",
                "fapi-ciba-id1-ensure-authorization-request-with-potentially-bad-binding-message",
                "fapi-ciba-id1-ensure-client-assertion-with-iss-aud-to-token-endpoint-succeeds",
                "fapi-ciba-id1-ensure-mtls-holder-of-key-required");
    }

    // The user denies the request on the authentication device
    protected Stream<ConformanceModuleVariant> userRejectsModules() {
        return modules(ConformanceResult.PASSED, BrowserInteraction.NONE,
                "fapi-ciba-id1-user-rejects-authentication");
    }

    // Modules that call the resource endpoint fail on the known Keycloak gaps only, see knownFailures
    protected Stream<ConformanceModuleVariant> resourceModules() {
        return modules(ConformanceResult.FAILED, BrowserInteraction.NONE,
                "fapi-ciba-id1",
                "fapi-ciba-id1-ensure-authorization-request-with-binding-message-succeeds",
                "fapi-ciba-id1-ensure-other-scope-order-succeeds",
                "fapi-ciba-id1-ensure-requested-expiry-as-string-succeeds",
                "fapi-ciba-id1-refresh-token");
    }

    // The clients sign with ES256 keys, so the suite cannot create RS256 signatures and skips
    protected Stream<ConformanceModuleVariant> rs256Modules() {
        return modules(ConformanceResult.SKIPPED, BrowserInteraction.NONE,
                "fapi-ciba-id1-ensure-request-object-signature-algorithm-is-RS256-fails",
                "fapi-ciba-id1-ensure-client-assertion-signature-algorithm-in-backchannel-authorization-request-is-RS256-fails",
                "fapi-ciba-id1-ensure-client-assertion-signature-algorithm-in-token-endpoint-request-is-RS256-fails");
    }

    @Override
    protected JsonNode suiteConfig(ConformanceModuleVariant module) {
        return FapiCibaSuiteConfig.create(OpenIdConformanceServer.keycloakBaseUri(), callbackDelay()).toJson();
    }
}
