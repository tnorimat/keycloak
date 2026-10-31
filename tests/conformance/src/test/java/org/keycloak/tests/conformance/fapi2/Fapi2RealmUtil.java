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


import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.ParConfig;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.tests.conformance.ConformanceRealmUtil;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Shared building blocks for the FAPI 2.0 conformance realms. Both the Security Profile and the Message Signing realm
 * register two confidential clients authenticating with private_key_jwt and enforce one of Keycloak's built-in
 * FAPI 2.0 DPoP client profiles on every client through a client policy.
 *
 * The client profiles auto-configure some client settings (PKCE, DPoP binding, consent) only when a client is
 * registered or updated, which does not happen on realm import, so the clients set these explicitly. Consent stays
 * disabled so the login flow needs no extra browser step; the user-rejects-authentication module enables it.
 */
public final class Fapi2RealmUtil {

    public static final String REALM = "fapi";
    public static final String USER = "john";
    public static final String PASSWORD = "password";
    public static final String CLIENT = "fapi-client";
    public static final String CLIENT2 = "fapi-client2";
    public static final String SCOPE = "openid profile";
    public static final String CONFORMANCE_CALLBACK = OpenIdConformanceServer.INTERNAL_BASE_URI + "/test/a/keycloak/callback";

    public static final String FAPI2_DPOP_SECURITY_PROFILE = "fapi-2-dpop-security-profile";
    public static final String FAPI2_DPOP_MESSAGE_SIGNING_PROFILE = "fapi-2-dpop-message-signing";

    private Fapi2RealmUtil() {
    }

    /**
     * Configures the FAPI conformance realm enforcing the given built-in client profile on every client.
     */
    public static RealmBuilder applyCommon(RealmBuilder realm, String clientProfile) {
        return realm.name(REALM)
                .eventsEnabled(true)
                .eventsListeners("jboss-logging")
                // FAPI 2.0 only permits PS256, ES256 and EdDSA, so the realm signs tokens with ES256
                .defaultSignatureAlgorithm(Algorithm.ES256)
                // The expired authorization code tests wait 62 seconds, just past Keycloak's default code lifespan of
                // 60 seconds, so a backward correction of the system clock during the wait made them fail
                // intermittently. A shorter lifespan leaves a margin.
                .accessCodeLifespan(30)
                .users(UserBuilder.create()
                        .username(USER)
                        .enabled(true)
                        .email("john@example.test")
                        .emailVerified(true)
                        .firstName("John")
                        .lastName("Doe")
                        .password(PASSWORD))
                .clients(fapiClient(CLIENT, false, Fapi2ClientKey.publicJwks()),
                        fapiClient(CLIENT2, true, Fapi2ClientKey.publicJwks2()))
                .clientPolicy(ConformanceRealmUtil.clientPolicy(clientProfile))
                .update(ConformanceRealmUtil::applyEs256SigningKey);
    }

    public static ClientBuilder fapiClient(String clientId, boolean wildcardRedirect, JsonNode publicJwks) {
        return ClientBuilder.create(clientId)
                .serviceAccountsEnabled(false)
                .directAccessGrantsEnabled(false)
                .consentRequired(false)
                .authenticatorType(JWTClientAuthenticator.PROVIDER_ID)
                .attribute(OIDCConfigAttributes.USE_JWKS_STRING, "true")
                .attribute(OIDCConfigAttributes.JWKS_STRING, publicJwks.toString())
                .attribute(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, Algorithm.ES256)
                .attribute(OIDCConfigAttributes.REQUEST_OBJECT_SIGNATURE_ALG, Algorithm.ES256)
                .attribute(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG, Algorithm.ES256)
                .attribute(OIDCConfigAttributes.PKCE_CODE_CHALLENGE_METHOD, "S256")
                .attribute(OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS, "true")
                .attribute(ParConfig.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS, "true")
                // The suite warns about Keycloak's typ and sid claims and the unrequested email claims in the ID token
                .protocolMappers(ConformanceRealmUtil.idTokenScriptMapper("conformance id token claims", "fapi-id-token-claims.js"))
                .redirectUris(CONFORMANCE_CALLBACK + (wildcardRedirect ? "*" : ""))
                .webOrigins(OpenIdConformanceServer.INTERNAL_BASE_URI.toString());
    }
}
