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

import java.util.HashMap;
import java.util.Map;

import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.tests.conformance.oidc.configs.OidcRealmConfig;

/**
 * The OpenID Connect Core realm with the suite's post_logout_redirect_uri registered on the clients, for the
 * RP-initiated logout and session management plans. Front-channel logout is disabled, so Keycloak redirects to the
 * post_logout_redirect_uri straight away; the front- and back-channel logout realms enable their logout mechanism.
 */
public class OidcLogoutRealmConfig extends OidcRealmConfig {

    // The suite's post_logout_redirect_uri: the redirect_uri with callback replaced by post_logout_redirect
    public static final String POST_LOGOUT_REDIRECT_URI = OpenIdConformanceServer.INTERNAL_BASE_URI + "/test/a/keycloak/post_logout_redirect";

    @Override
    public RealmBuilder configure(RealmBuilder realm) {
        return super.configure(realm).update(rep -> rep.getClients().forEach(this::configureLogout));
    }

    protected void configureLogout(ClientRepresentation client) {
        // Without the ID token mappers of the OpenID Connect Core realm: Keycloak checks the typ claim of the
        // id_token_hint of a logout request, which the mapper removing typ would break
        client.setProtocolMappers(null);
        client.setFrontchannelLogout(false);
        Map<String, String> attributes = client.getAttributes() != null ? new HashMap<>(client.getAttributes()) : new HashMap<>();
        attributes.put(OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, POST_LOGOUT_REDIRECT_URI);
        client.setAttributes(attributes);
    }
}
