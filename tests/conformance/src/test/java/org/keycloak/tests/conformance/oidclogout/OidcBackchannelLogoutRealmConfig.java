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

import java.net.URI;

import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;

/**
 * Registers the suite's backchannel_logout_uri. Keycloak sends the logout token itself and runs outside the container
 * network, so the clients register the endpoint at the suite's address on the Docker host instead of its internal
 * address.
 */
public class OidcBackchannelLogoutRealmConfig extends OidcLogoutRealmConfig {

    @Override
    protected void configureLogout(ClientRepresentation client) {
        super.configureLogout(client);
        URI backchannelLogoutUri = OpenIdConformanceServer.instance().externalUri(
                URI.create(OpenIdConformanceServer.INTERNAL_BASE_URI + "/test/a/keycloak/backchannel_logout"));
        client.getAttributes().put(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_URL, backchannelLogoutUri.toString());
        client.getAttributes().put(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_SESSION_REQUIRED, "true");
    }
}
