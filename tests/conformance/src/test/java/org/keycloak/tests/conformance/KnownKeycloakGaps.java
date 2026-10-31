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

/**
 * Suite conditions failing on Keycloak gaps that the conformance tests of several specifications run into. Tests expect
 * the affected modules to finish with FAILED and declare these conditions as their known failures, see
 * {@link AbstractConformanceTest#knownFailures}. The optional {@code KeycloakProxy} of the conformance runner works
 * around the missing resource endpoint response headers.
 */
public final class KnownKeycloakGaps {

    // TODO: Keycloak does not send the Date header the suite requires on resource endpoint responses (RFC 9110
    //  section 6.6.1), which the FAPI conformance tests check on Keycloak's userinfo endpoint. Expect the affected
    //  modules to pass once Keycloak sends it.
    public static final String MISSING_DATE_HEADER = "CheckForDateHeaderInResourceResponse";

    private KnownKeycloakGaps() {
    }
}
