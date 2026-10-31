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

import java.net.URI;
import java.util.List;

import org.keycloak.testframework.conformance.runner.BrowserFlow;
import org.keycloak.testframework.conformance.runner.BrowserInteraction;
import org.keycloak.testframework.conformance.runner.SuiteOptions;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.CLIENT;
import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.CLIENT2;
import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.CONFORMANCE_CALLBACK;
import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.PASSWORD;
import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.REALM;
import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.SCOPE;
import static org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil.USER;

/**
 * The test configuration uploaded to the conformance suite for the FAPI 2.0 plans. The suite calls the resource
 * endpoint with the sender constrained access token, for which Keycloak's userinfo endpoint is used.
 */
record Fapi2SuiteConfig(
        String alias,
        Server server,
        Client client,
        Client client2,
        Resource resource,
        List<BrowserFlow> browser,
        SuiteOptions options) {

    static Fapi2SuiteConfig create(URI keycloakBaseUri, BrowserInteraction browserInteraction) {
        String realmUri = keycloakBaseUri + "/realms/" + REALM;
        return new Fapi2SuiteConfig(
                "keycloak",
                new Server(realmUri + "/.well-known/openid-configuration"),
                new Client(CLIENT, SCOPE, Fapi2ClientKey.privateJwks()),
                new Client(CLIENT2, SCOPE, Fapi2ClientKey.privateJwks2()),
                new Resource(realmUri + "/protocol/openid-connect/userinfo"),
                browserInteraction.browserFlows(new BrowserInteraction.BrowserContext(
                        REALM,
                        USER,
                        PASSWORD,
                        CONFORMANCE_CALLBACK)),
                SuiteOptions.WITHOUT_BROWSER_CSS);
    }

    JsonNode toJson() {
        return JsonSerialization.writeValueAsNode(this);
    }

    record Server(@JsonProperty("discoveryUrl") String discoveryUrl) {
    }

    record Client(
            @JsonProperty("client_id") String clientId,
            @JsonProperty("scope") String scope,
            @JsonProperty("jwks") JsonNode jwks) {
    }

    record Resource(@JsonProperty("resourceUrl") String resourceUrl) {
    }
}
