/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.clientpolicy.executor;

import java.util.Arrays;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorFactory;

public class TestClientAuthenticationExecutorFactory implements ClientPolicyExecutorFactory {

    public static final String PROVIDER_ID = "test-client-authn-executor";

    public static final String CLIENT_AUTHNS = "client-authns";
    public static final String CLIENT_AUTHNS_AUGMENT = "client-authns-augment";

    private static final ProviderConfigProperty CLIENTAUTHNS_PROPERTY = new ProviderConfigProperty(
            CLIENT_AUTHNS, null, null, ProviderConfigProperty.MULTIVALUED_STRING_TYPE, null);
    private static final ProviderConfigProperty CLIENTAUTHNS_IS_AUGMENT_PROPERTY = new ProviderConfigProperty(
            ClientPolicyExecutorFactory.IS_AUGMENT, null, null, ProviderConfigProperty.BOOLEAN_TYPE, false);
    private static final ProviderConfigProperty CLIENTAUTHNS_AUGMENT = new ProviderConfigProperty(
            CLIENT_AUTHNS_AUGMENT, null, null, ProviderConfigProperty.STRING_TYPE, JWTClientAuthenticator.PROVIDER_ID);

    @Override
    public ClientPolicyExecutor create(KeycloakSession session, ComponentModel model) {
        return new TestClientAuthenticationExecutor(session, model);
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(CLIENTAUTHNS_PROPERTY, CLIENTAUTHNS_IS_AUGMENT_PROPERTY, CLIENTAUTHNS_AUGMENT);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(KeycloakSession session) {
        return Arrays.asList(CLIENTAUTHNS_PROPERTY, CLIENTAUTHNS_IS_AUGMENT_PROPERTY, CLIENTAUTHNS_AUGMENT);
    }
}
