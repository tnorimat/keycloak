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

import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.CibaConfig;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.tests.conformance.ConformanceRealmUtil;
import org.keycloak.tests.conformance.ConformanceSigningKey;

/**
 * The FAPI-CIBA conformance realm for the poll mode. Both clients use CIBA with private_key_jwt client
 * authentication, signed authentication requests and certificate bound access tokens, and are subject to Keycloak's
 * built-in {@code fapi-1-advanced} and {@code fapi-ciba} client profiles. The suite identifies the user with a
 * login_hint carrying the username.
 *
 * As with the FAPI 2.0 realms, the client profiles auto-configure settings only on client registration, which does
 * not happen on realm import, so the clients set them explicitly.
 */
public class FapiCibaRealmConfig implements RealmConfig {

    public static final String REALM = "fapiciba";
    public static final String USER = "john";
    public static final String PASSWORD = "password";
    public static final String CLIENT = "fapiciba-client";
    public static final String CLIENT2 = "fapiciba-client2";
    public static final String SCOPE = "openid profile";

    @Override
    public RealmBuilder configure(RealmBuilder realm) {
        return realm.name(REALM)
                .eventsEnabled(true)
                .eventsListeners("jboss-logging")
                .defaultSignatureAlgorithm(Algorithm.ES256)
                .attribute(CibaConfig.CIBA_AUTH_REQUESTED_USER_HINT, CibaConfig.DEFAULT_CIBA_POLICY_AUTH_REQUESTED_USER_HINT)
                .users(UserBuilder.create()
                        .username(USER)
                        .enabled(true)
                        .email("john@example.test")
                        .emailVerified(true)
                        .firstName("John")
                        .lastName("Doe")
                        .password(PASSWORD))
                .clients(cibaClient(CLIENT, FapiCibaClientKey.CLIENT), cibaClient(CLIENT2, FapiCibaClientKey.CLIENT2))
                .clientPolicy(ConformanceRealmUtil.clientPolicy("fapi-1-advanced", "fapi-ciba"))
                .update(ConformanceRealmUtil::applyEs256SigningKey);
    }

    protected ClientBuilder cibaClient(String clientId, ConformanceSigningKey key) {
        return ClientBuilder.create(clientId)
                .serviceAccountsEnabled(false)
                .directAccessGrantsEnabled(false)
                .consentRequired(false)
                .authenticatorType(JWTClientAuthenticator.PROVIDER_ID)
                .attribute(OIDCConfigAttributes.USE_JWKS_STRING, "true")
                .attribute(OIDCConfigAttributes.JWKS_STRING, key.publicJwks().toString())
                .attribute(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, Algorithm.ES256)
                .attribute(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG, Algorithm.ES256)
                .attribute(OIDCConfigAttributes.USE_MTLS_HOK_TOKEN, "true")
                .attribute(CibaConfig.OIDC_CIBA_GRANT_ENABLED, "true")
                .attribute(CibaConfig.CIBA_BACKCHANNEL_AUTH_REQUEST_SIGNING_ALG, Algorithm.ES256)
                .attribute(CibaConfig.CIBA_BACKCHANNEL_TOKEN_DELIVERY_MODE_PER_CLIENT, CibaConfig.CIBA_POLL_MODE)
                .redirectUris(OpenIdConformanceServer.INTERNAL_BASE_URI + "/test/a/keycloak/callback")
                .webOrigins(OpenIdConformanceServer.INTERNAL_BASE_URI.toString());
    }
}
