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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.json.RawJsonValue;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.GeneratedEcdsaKeyProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.ClaimsParameterTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.idm.ClientPolicyConditionRepresentation;
import org.keycloak.representations.idm.ClientPolicyRepresentation;
import org.keycloak.representations.idm.ComponentExportRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.clientpolicy.condition.AnyClientConditionFactory;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;

/**
 * Realm building blocks shared by the conformance tests of several specifications, e.g. the FAPI ones.
 */
public final class ConformanceRealmUtil {

    private ConformanceRealmUtil() {
    }

    /**
     * A client policy enforcing the given client profiles, e.g. Keycloak's built-in FAPI profiles, on every client.
     */
    public static ClientPolicyRepresentation clientPolicy(String... clientProfiles) {
        ClientPolicyConditionRepresentation condition = new ClientPolicyConditionRepresentation();
        condition.setConditionProviderId(AnyClientConditionFactory.PROVIDER_ID);
        condition.setConfiguration(RawJsonValue.of(JsonNodeFactory.instance.objectNode()));

        ClientPolicyRepresentation policy = new ClientPolicyRepresentation();
        policy.setName("conformance-policy");
        policy.setDescription("Enforces " + String.join(", ", clientProfiles) + " on every client");
        policy.setEnabled(true);
        policy.setConditions(List.of(condition));
        policy.setProfiles(List.of(clientProfiles));
        return policy;
    }

    /**
     * Adds a generated ES256 signing key to the realm. FAPI only permits PS256, ES256 and EdDSA, so the FAPI realms sign
     * with it.
     */
    public static void applyEs256SigningKey(RealmRepresentation rep) {
        MultivaluedHashMap<String, ComponentExportRepresentation> components = rep.getComponents();
        if (components == null) {
            components = new MultivaluedHashMap<>();
            rep.setComponents(components);
        }
        ComponentExportRepresentation keyProvider = new ComponentExportRepresentation();
        keyProvider.setName("conformance-es256-key");
        keyProvider.setId(UUID.randomUUID().toString());
        keyProvider.setProviderId(GeneratedEcdsaKeyProviderFactory.ID);
        keyProvider.setConfig(new MultivaluedHashMap<>(Map.of(
                Attributes.PRIORITY_KEY, List.of("100"),
                Attributes.ENABLED_KEY, List.of("true"),
                Attributes.ACTIVE_KEY, List.of("true"),
                GeneratedEcdsaKeyProviderFactory.ECDSA_ELLIPTIC_CURVE_KEY, List.of("P-256"))));
        components.add(KeyProvider.class.getName(), keyProvider);
    }

    /**
     * An ID token mapper running one of the scripts of this module (src/main/resources/META-INF/keycloak-scripts.json),
     * which the conformance servers deploy. Script mappers run after the attribute and property mappers, so they can
     * remove the claims those add.
     */
    public static ProtocolMapperRepresentation idTokenScriptMapper(String name, String fileName) {
        return idTokenMapper(name, "script-" + fileName);
    }

    /**
     * Keycloak's claims parameter mapper, which returns the essential identity claims requested with the claims
     * parameter, e.g. name, in the ID token and from the userinfo endpoint.
     */
    public static ProtocolMapperRepresentation claimsParameterMapper() {
        ProtocolMapperRepresentation mapper = idTokenMapper("claims parameter", ClaimsParameterTokenMapper.PROVIDER_ID);
        mapper.getConfig().put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
        return mapper;
    }

    private static ProtocolMapperRepresentation idTokenMapper(String name, String providerId) {
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName(name);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        mapper.setProtocolMapper(providerId);
        mapper.setConfig(new HashMap<>(Map.of(
                OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true",
                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "false",
                OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "false")));
        return mapper;
    }
}
