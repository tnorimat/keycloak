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

import java.net.URI;
import java.time.Duration;

import org.keycloak.testframework.conformance.ciba.CibaAuthenticationDevice;
import org.keycloak.tests.conformance.ConformanceSigningKey;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import static org.keycloak.tests.conformance.fapiciba.FapiCibaRealmConfig.CLIENT;
import static org.keycloak.tests.conformance.fapiciba.FapiCibaRealmConfig.CLIENT2;
import static org.keycloak.tests.conformance.fapiciba.FapiCibaRealmConfig.REALM;
import static org.keycloak.tests.conformance.fapiciba.FapiCibaRealmConfig.SCOPE;
import static org.keycloak.tests.conformance.fapiciba.FapiCibaRealmConfig.USER;

/**
 * The test configuration uploaded to the conformance suite for the FAPI-CIBA plan. The suite approves or denies the
 * CIBA requests through the {@link CibaAuthenticationDevice}, and calls Keycloak's userinfo endpoint as the resource
 * endpoint with the certificate bound access token.
 */
record FapiCibaSuiteConfig(
        String alias,
        Server server,
        Client client,
        Client client2,
        Mtls mtls,
        Mtls mtls2,
        Resource resource,
        @JsonProperty("automated_ciba_approval_url") String automatedCibaApprovalUrl) {

    static FapiCibaSuiteConfig create(URI keycloakBaseUri, Duration callbackDelay) {
        String realmUri = keycloakBaseUri + "/realms/" + REALM;
        return new FapiCibaSuiteConfig(
                "keycloak",
                new Server(realmUri + "/.well-known/openid-configuration"),
                Client.of(CLIENT, FapiCibaClientKey.CLIENT),
                Client.of(CLIENT2, FapiCibaClientKey.CLIENT2),
                Mtls.of(FapiCibaClientKey.CLIENT),
                Mtls.of(FapiCibaClientKey.CLIENT2),
                new Resource(realmUri + "/protocol/openid-connect/userinfo"),
                CibaAuthenticationDevice.instance().automatedApprovalUrl(callbackDelay));
    }

    JsonNode toJson() {
        return JsonSerialization.writeValueAsNode(this);
    }

    record Server(@JsonProperty("discoveryUrl") String discoveryUrl) {
    }

    record Client(
            @JsonProperty("client_id") String clientId,
            @JsonProperty("scope") String scope,
            @JsonProperty("jwks") JsonNode jwks,
            @JsonProperty("hint_type") String hintType,
            @JsonProperty("hint_value") String hintValue,
            // a value of Keycloak's acr_values_supported, which the suite requests in the happy flow
            @JsonProperty("acr_value") String acrValue) {

        static Client of(String clientId, ConformanceSigningKey key) {
            return new Client(clientId, SCOPE, key.privateJwks(), "login_hint", USER, "1");
        }
    }

    record Mtls(
            @JsonProperty("key") String key,
            @JsonProperty("cert") String cert,
            @JsonProperty("ca") String ca) {

        static Mtls of(ConformanceSigningKey key) {
            return new Mtls(key.privateKeyPem(), key.certificatePem(), key.caCertificatePem());
        }
    }

    record Resource(@JsonProperty("resourceUrl") String resourceUrl) {
    }
}
