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

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.keycloak.testframework.config.Config;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.conformance.annotations.InjectOpenIdConformanceServer;
import org.keycloak.testframework.conformance.runner.BrowserInteraction;
import org.keycloak.testframework.conformance.runner.ConformanceModuleResult;
import org.keycloak.testframework.conformance.runner.ConformanceModuleVariant;
import org.keycloak.testframework.conformance.runner.ConformanceResult;
import org.keycloak.testframework.conformance.runner.ModuleRun;
import org.keycloak.testframework.https.CertificatesConfig;
import org.keycloak.testframework.https.CertificatesConfigBuilder;
import org.keycloak.testframework.https.InjectCertificates;
import org.keycloak.testframework.https.ManagedCertificates;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Base class for all conformance areas. Test classes inject a realm and implement {@link #moduleVariants()},
 * either listing the variants explicitly or using {@link #discoverModuleVariants}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractConformanceTest {

    private static final Logger LOGGER = Logger.getLogger(AbstractConformanceTest.class);

    /**
     * How often a module not finishing as expected is run again before the test fails, as modules occasionally fail
     * for reasons outside of Keycloak, e.g. network errors or the timing of the suite's waits. Set it with the
     * {@value} test framework option (system property, {@code KC_TEST_CONFORMANCE_RETRIES} environment variable or
     * keycloak-test.properties); 0 disables the retries.
     */
    public static final String RETRIES_PROPERTY = "kc.test.conformance.retries";

    private static final int DEFAULT_RETRIES = 3;

    @InjectCertificates(config = TlsCertificates.class)
    protected ManagedCertificates certificates;

    @InjectOpenIdConformanceServer
    protected OpenIdConformanceServer server;

    protected abstract Stream<ConformanceModuleVariant> moduleVariants();

    protected abstract JsonNode suiteConfig(ConformanceModuleVariant moduleVariant);

    /**
     * Discovers all variant combinations of a module from the plan. Runs while tests are collected, before the
     * test framework injects the suite, hence the singleton access.
     */
    protected Stream<ConformanceModuleVariant> discoverModuleVariants(String plan, Map<String, String> planVariant, String name) {
        return discoverModuleVariants(plan, planVariant, name, ConformanceResult.PASSED, BrowserInteraction.NONE);
    }

    protected Stream<ConformanceModuleVariant> discoverModuleVariants(String plan, Map<String, String> planVariant,
            String name, ConformanceResult expectedResult, BrowserInteraction browserInteraction) {
        ConformanceModuleVariant template = new ConformanceModuleVariant(plan, planVariant, name, Map.of(),
                expectedResult, browserInteraction);
        return OpenIdConformanceServer.instance().client()
                .discoverModuleVariants(plan, planVariant, name, suiteConfig(template))
                .map(moduleVariant -> new ConformanceModuleVariant(plan, planVariant, name, moduleVariant,
                        expectedResult, browserInteraction));
    }

    /**
     * Discovers all variant combinations of every named module from a single created plan. The modules share the
     * same browser interaction and expected result, so a single test class can host a group of related modules.
     */
    protected Stream<ConformanceModuleVariant> discoverModuleVariants(String plan, Map<String, String> planVariant,
            List<String> names, ConformanceResult expectedResult, BrowserInteraction browserInteraction) {
        ConformanceModuleVariant template = new ConformanceModuleVariant(plan, planVariant, names.get(0), Map.of(),
                expectedResult, browserInteraction);
        Map<String, List<Map<String, String>>> discovered = OpenIdConformanceServer.instance().client()
                .discoverModuleVariants(plan, planVariant, names, suiteConfig(template));
        return names.stream().flatMap(name -> discovered.get(name).stream()
                .map(moduleVariant -> new ConformanceModuleVariant(plan, planVariant, name, moduleVariant,
                        expectedResult, browserInteraction)));
    }

    /**
     * Drives the system under test once the module waits for it, for example delivers an OID4VP verifier request or
     * the credential offer the issuer initiated modules wait for.
     */
    protected Consumer<ModuleRun> interaction(ConformanceModuleVariant moduleVariant) {
        return null;
    }

    /**
     * The only suite conditions a module expected to finish FAILED may fail on, so that a known Keycloak gap does not
     * mask other failures of the module. A module is expected to finish FAILED only because of such known gaps, so
     * without any, e.g. as the test setup works around them, the module is expected to finish with
     * {@link #resultWithoutKnownFailures}.
     */
    protected Set<String> knownFailures(ConformanceModuleVariant moduleVariant) {
        return Set.of();
    }

    /**
     * The result a module expected to finish FAILED finishes with when it has no {@link #knownFailures}, usually
     * PASSED. A failure can hide what the module finishes with otherwise, e.g. a WARNING or a REVIEW.
     */
    protected ConformanceResult resultWithoutKnownFailures(ConformanceModuleVariant moduleVariant) {
        return ConformanceResult.PASSED;
    }

    @ParameterizedTest
    @MethodSource("moduleVariants")
    public void conformance(ConformanceModuleVariant moduleVariant) {
        ConformanceResult expectedResult = moduleVariant.expectedResult();
        Set<String> knownFailures = expectedResult == ConformanceResult.FAILED ? knownFailures(moduleVariant) : Set.of();
        if (expectedResult == ConformanceResult.FAILED && knownFailures.isEmpty()) {
            expectedResult = resultWithoutKnownFailures(moduleVariant);
        }

        int attempts = 1 + Math.max(0, Config.get(RETRIES_PROPERTY, DEFAULT_RETRIES, Integer.class));
        for (int attempt = 1; ; attempt++) {
            // Each run creates a new plan, so an attempt does not depend on the previous one
            ConformanceModuleResult result = server.client()
                    .run(moduleVariant, suiteConfig(moduleVariant), interaction(moduleVariant));
            String failure = failure(result, expectedResult, knownFailures);
            if (failure == null) {
                if (attempt > 1) {
                    printRetryNotice("Conformance module " + result.module() + " " + moduleVariant.moduleVariant()
                            + " finished as expected in attempt " + attempt + " of " + attempts);
                }
                return;
            }
            if (attempt < attempts) {
                printRetryNotice("Attempt " + attempt + " of " + attempts + " of conformance module " + result.module()
                        + " did not finish as expected, running it again:\n" + failure);
                continue;
            }
            // Formatted upfront, as the test framework log filter replays buffered records without their parameters
            LOGGER.error("Full logs of failed conformance module " + result.module() + ":\n" + result.logs().toPrettyString());
            Assertions.fail((attempts > 1 ? "All " + attempts + " attempts failed, the last one with:\n" : "") + failure);
        }
    }

    /**
     * Prints to the test output rather than logging, as the test framework log filter drops the logs of a test that
     * passes, which would hide that a module passed only when run again.
     */
    private static void printRetryNotice(String message) {
        System.out.println("[conformance retry] " + message);
    }

    /**
     * Why the module did not finish as expected, or {@code null} if it did.
     */
    private static String failure(ConformanceModuleResult result, ConformanceResult expectedResult,
            Set<String> knownFailures) {
        boolean unknownFailures = expectedResult == ConformanceResult.FAILED
                && !knownFailures.containsAll(result.failedConditions());
        if (result.finishedWith(expectedResult) && !unknownFailures) {
            return null;
        }
        return result.failureSummary()
                + (unknownFailures ? "\n  failed conditions " + result.failedConditions()
                        + " beyond the known failures " + knownFailures : "");
    }

    public static class TlsCertificates implements CertificatesConfig {

        @Override
        public CertificatesConfigBuilder configure(CertificatesConfigBuilder config) {
            return config.tlsEnabled(true);
        }
    }
}
