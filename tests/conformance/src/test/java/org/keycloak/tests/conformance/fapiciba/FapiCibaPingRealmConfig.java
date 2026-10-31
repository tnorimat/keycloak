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

import org.keycloak.models.CibaConfig;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.tests.conformance.ConformanceSigningKey;

/**
 * The FAPI-CIBA conformance realm for the ping mode. Keycloak notifies the suite's client notification endpoint,
 * which the suite publishes on its internal host; Keycloak runs outside the container network, so the clients
 * register the endpoint at the suite's address on the Docker host instead.
 */
public class FapiCibaPingRealmConfig extends FapiCibaRealmConfig {

    @Override
    protected ClientBuilder cibaClient(String clientId, ConformanceSigningKey key) {
        URI notificationEndpoint = OpenIdConformanceServer.instance().externalUri(
                URI.create(OpenIdConformanceServer.INTERNAL_BASE_URI + "/test/a/keycloak/ciba-notification-endpoint"));
        return super.cibaClient(clientId, key)
                .attribute(CibaConfig.CIBA_BACKCHANNEL_TOKEN_DELIVERY_MODE_PER_CLIENT, CibaConfig.CIBA_PING_MODE)
                .attribute(CibaConfig.CIBA_BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT, notificationEndpoint.toString());
    }
}
