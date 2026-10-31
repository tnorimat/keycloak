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

/**
 * The FAPI 2.0 Message Signing modules that run against the default realm, grouped by the browser interaction they
 * need. Modules that need a dedicated realm configuration live in their own test classes.
 */
@KeycloakIntegrationTest(config = ConformanceServerConfig.class)
public class Fapi2MessageSigningTest extends AbstractFapi2MessageSigningTest {

    @InjectRealm(config = Fapi2MessageSigningRealmConfig.class)
    ManagedRealm realm;

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        return Stream.of(
                // Rejected before the authorization endpoint is visited (the request object signature is verified
                // at the PAR endpoint), or not using the browser at all
                modules(ConformanceResult.PASSED, BrowserInteraction.NONE,
                        "fapi2-security-profile-final-discovery-end-point-verification",
                        "fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param",
                        "fapi2-security-profile-final-par-authorization-request-containing-request_uri",
                        "fapi2-security-profile-final-par-attempt-invalid-http-method",
                        "fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails",
                        "fapi2-security-profile-final-ensure-request-object-signature-algorithm-is-not-none",
                        "fapi2-security-profile-final-ensure-request-object-with-invalid-signature-fails",
                        "fapi2-security-profile-final-ensure-matching-key-in-authorization-request",
                        "fapi2-security-profile-final-par-ensure-jwt-client-assertions-nbf-over-60-seconds-in-the-future-fails",
                        "fapi2-security-profile-final-par-test-array-as-audience-fails",
                        "fapi2-security-profile-final-par-test-par-endpoint-url-as-audience-fails",
                        "fapi2-security-profile-final-par-test-token-endpoint-url-as-audience-fails"),
                // Rejected at the authorization endpoint with an error redirected to the callback. The request object
                // claims (exp, nbf, aud) and the match with the query parameters are checked by the
                // secure-request-object executor on the authorization request only, so the PAR endpoint accepts
                // such request objects.
                modules(ConformanceResult.PASSED, BrowserInteraction.ERROR_CALLBACK,
                        "fapi2-security-profile-final-ensure-request-object-without-exp-fails",
                        "fapi2-security-profile-final-ensure-request-object-without-nbf-fails",
                        "fapi2-security-profile-final-ensure-expired-request-object-fails",
                        "fapi2-security-profile-final-ensure-request-object-with-bad-aud-fails",
                        "fapi2-security-profile-final-ensure-request-object-with-exp-over-60-fails",
                        "fapi2-security-profile-final-ensure-request-object-with-nbf-over-60-fails",
                        "fapi2-security-profile-final-ensure-unsigned-request-at-par-endpoint-fails",
                        "fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object",
                        "fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object",
                        "fapi2-security-profile-final-par-ensure-pkce-required",
                        "fapi2-security-profile-final-par-plain-pkce-rejected"),
                // Modules that do not call the resource endpoint
                modules(ConformanceResult.PASSED, BrowserInteraction.LOGIN,
                        "fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri",
                        "fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request",
                        "fapi2-security-profile-final-ensure-response-type-code-idtoken-fails",
                        "fapi2-security-profile-final-ensure-response-type-token-fails",
                        "fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails",
                        "fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt",
                        "fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt",
                        "fapi2-security-profile-final-ensure-client-id-in-token-endpoint",
                        "fapi2-security-profile-final-ensure-holder-of-key-required",
                        "fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client",
                        "fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code",
                        "fapi2-security-profile-final-ensure-client-assertion-in-token-endpoint",
                        "fapi2-security-profile-final-ensure-client-assertion-with-exp-is-5-minutes-in-past-fails",
                        "fapi2-security-profile-final-ensure-client-assertion-with-wrong-aud-fails",
                        "fapi2-security-profile-final-ensure-client-assertion-with-no-sub-fails",
                        "fapi2-security-profile-final-ensure-pkce-code-verifier-required",
                        "fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected"),
                // Modules that call the resource endpoint fail on the known Keycloak gaps only, see knownFailures
                modules(ConformanceResult.FAILED, BrowserInteraction.LOGIN,
                        "fapi2-security-profile-final-happy-flow",
                        "fapi2-security-profile-final-ensure-request-object-with-multiple-aud-succeeds",
                        "fapi2-security-profile-final-ensure-authorization-request-without-state-success",
                        "fapi2-security-profile-final-ensure-authorization-request-without-nonce-success",
                        "fapi2-security-profile-final-ensure-authorization-request-with-64-char-nonce-success",
                        "fapi2-security-profile-final-ensure-other-scope-order-succeeds",
                        "fapi2-security-profile-final-access-token-type-header-case-sensitivity",
                        "fapi2-security-profile-final-ensure-request-object-with-nbf-8-seconds-in-the-future-is-accepted",
                        "fapi2-security-profile-final-check-dpop-proof-nbf-exp",
                        "fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds",
                        "fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds",
                        "fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success",
                        "fapi2-security-profile-final-ensure-dpop-auth-code-binding-success",
                        "fapi2-security-profile-final-ensure-authorization-request-with-long-nonce",
                        "fapi2-security-profile-final-ensure-authorization-request-with-long-state",
                        "fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second",
                        "fapi2-security-profile-final-dpop-negative-tests",
                        "fapi2-security-profile-final-refresh-token",
                        "fapi2-security-profile-final-par-ensure-jwt-client-assertions-nbf-8-seconds-in-the-future-is-accepted",
                        "fapi2-security-profile-final-par-without-duplicate-parameters"),
                // Passes as the script based ID token mapper of the realm removes the claims Keycloak always adds and
                // the suite warns about (typ, sid), see Fapi2RealmUtil
                modules(ConformanceResult.PASSED, BrowserInteraction.LOGIN,
                        "fapi2-security-profile-final-test-claims-parameter-identity-claims"),
                // The clients sign with ES256 keys, so the suite cannot create the RS256 client assertion and request
                // object and skips
                modules(ConformanceResult.SKIPPED, BrowserInteraction.NONE,
                        "fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails",
                        "fapi2-security-profile-final-ensure-signed-request-object-with-RS256-fails"),
                // The first authorization only loads the login page, so the request_uri stays valid for the second.
                // The module calls the resource endpoint, so it fails on the known Keycloak gaps only.
                modules(ConformanceResult.FAILED, BrowserInteraction.LOGIN_ON_SECOND_VISIT,
                        "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"),
                // Keycloak renders its error page on the second authorization. The first one calls the resource
                // endpoint, so the module fails on the known Keycloak gaps only.
                modules(ConformanceResult.FAILED,
                        BrowserInteraction.loginThenErrorPageOnSecondVisit("PAR not found, not issued or used multiple times."),
                        "fapi2-security-profile-final-par-attempt-reuse-request_uri"),
                // Keycloak renders its error page, which the suite snapshots for review
                modules(ConformanceResult.REVIEW, BrowserInteraction.errorPage("PAR request did not include query parameter"),
                        "fapi2-security-profile-final-state-only-outside-request-object-not-used"),
                modules(ConformanceResult.REVIEW, BrowserInteraction.errorPage("PAR request_uri not included."),
                        "fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails"))
                .flatMap(group -> group);
    }
}
