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

import java.util.Map;

import org.keycloak.tests.conformance.oidc.AbstractOidcConformanceTest;

/**
 * Baseline for the OpenID Connect logout certification plans, which run with discovery, static clients and the
 * authorization code flow.
 */
public abstract class AbstractOidcLogoutConformanceTest extends AbstractOidcConformanceTest {

    public static final String RP_INITIATED_LOGOUT_PLAN = "oidcc-rp-initiated-logout-certification-test-plan";
    public static final String FRONTCHANNEL_LOGOUT_PLAN = "oidcc-frontchannel-rp-initiated-logout-certification-test-plan";
    public static final String BACKCHANNEL_LOGOUT_PLAN = "oidcc-backchannel-rp-initiated-logout-certification-test-plan";
    public static final String SESSION_MANAGEMENT_PLAN = "oidcc-session-management-certification-test-plan";

    // The logout plans pin discovery themselves, but not the response type
    @Override
    protected Map<String, String> planVariant() {
        return Map.of(
                "client_registration", "static_client",
                "response_type", "code");
    }
}
