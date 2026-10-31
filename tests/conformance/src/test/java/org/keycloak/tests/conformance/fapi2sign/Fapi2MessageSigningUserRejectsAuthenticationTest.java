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
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.tests.conformance.ConformanceServerConfig;
import org.keycloak.tests.conformance.fapi2sign.configs.Fapi2MessageSigningRealmConfig;

/**
 * The user denies the consent, so the clients require consent here.
 */
@KeycloakIntegrationTest(config = ConformanceServerConfig.class)
public class Fapi2MessageSigningUserRejectsAuthenticationTest extends AbstractFapi2MessageSigningTest {

    @InjectRealm(config = ConsentRequiredRealmConfig.class)
    ManagedRealm realm;

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        return modules(ConformanceResult.PASSED, BrowserInteraction.DENY_CONSENT,
                "fapi2-security-profile-final-user-rejects-authentication");
    }

    public static class ConsentRequiredRealmConfig extends Fapi2MessageSigningRealmConfig {

        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return super.configure(realm).update(rep -> rep.getClients()
                    .forEach(client -> client.setConsentRequired(true)));
        }
    }
}
