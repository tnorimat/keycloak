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

import org.keycloak.tests.conformance.ConformanceSigningKey;

import com.fasterxml.jackson.databind.JsonNode;

import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.REALM;

/**
 * The client signing keys for private_key_jwt client authentication and signed request objects, generated at runtime
 * so no private key material is committed to the repository. The conformance suite holds the private JWKS while
 * Keycloak registers only the public JWKS on each client.
 */
public final class Fapi2ClientKey {

    // Two independent keys, one per conformance client, as the suite asserts the clients use different keys
    private static final ConformanceSigningKey KEY = ConformanceSigningKey.generate(
            REALM, "fapi_client_signing_key", "FAPI Conformance Client", null);

    private static final ConformanceSigningKey KEY2 = ConformanceSigningKey.generate(
            REALM, "fapi_client2_signing_key", "FAPI Conformance Client 2", null);

    private Fapi2ClientKey() {
    }

    public static JsonNode privateJwks() {
        return KEY.privateJwks();
    }

    public static JsonNode publicJwks() {
        return KEY.publicJwks();
    }

    public static JsonNode privateJwks2() {
        return KEY2.privateJwks();
    }

    public static JsonNode publicJwks2() {
        return KEY2.publicJwks();
    }
}
