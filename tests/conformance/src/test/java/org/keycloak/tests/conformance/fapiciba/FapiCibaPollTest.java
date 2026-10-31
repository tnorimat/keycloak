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
import org.keycloak.testframework.conformance.runner.ConformanceModuleVariant;
import org.keycloak.testframework.realm.ManagedRealm;

/**
 * The FAPI-CIBA modules in the poll mode.
 */
@KeycloakIntegrationTest(config = FapiCibaServerConfig.class)
public class FapiCibaPollTest extends AbstractFapiCibaConformanceTest {

    @InjectRealm(config = FapiCibaRealmConfig.class)
    ManagedRealm realm;

    @Override
    protected String cibaMode() {
        return CibaConfig.CIBA_POLL_MODE;
    }

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        return Stream.of(rejectingModules(), tokenModules(), userRejectsModules(), resourceModules(), rs256Modules())
                .flatMap(group -> group);
    }
}
