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

package org.keycloak.services.clientpolicy.condition.impl;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProvider;
import org.keycloak.services.clientpolicy.impl.ClientPolicyLogger;

public class TestAuthnMethodsCondition implements ClientPolicyConditionProvider {

    private static final Logger logger = Logger.getLogger(TestAuthnMethodsCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public TestAuthnMethodsCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public boolean isSatisfiedOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
        case DYNAMIC_REGISTER:
        case DYNAMIC_UPDATE:
            ClientUpdateContext clientUpdateContext = (ClientUpdateContext)context;
            return clientUpdateContext.getDynamicRegistrationAuth() == null ? false : isAuthMethodMatched(clientUpdateContext.getDynamicRegistrationAuth().name());
        case ADMIN_REGISTER:
        case ADMIN_UPDATE:
            return isAuthMethodMatched(TestAuthnMethodsConditionFactory.BY_ADMIN_REST_API);
        default:
            throw new ClientPolicyException(ClientPolicyConditionProvider.SKIP_EVALUATION, "");
        }
    }

    private boolean isAuthMethodMatched(String authMethod) {
        if (authMethod == null) return false;

        ClientPolicyLogger.log(logger, "auth method = " + authMethod);
        componentModel.getConfig().get(TestAuthnMethodsConditionFactory.AUTH_METHOD).stream().forEach(i -> ClientPolicyLogger.log(logger, "auth method expected = " + i));

        boolean isMatched = componentModel.getConfig().get(TestAuthnMethodsConditionFactory.AUTH_METHOD).stream().anyMatch(i -> i.equals(authMethod));
        if (isMatched) {
            ClientPolicyLogger.log(logger, "auth method matched.");
        } else {
            ClientPolicyLogger.log(logger, "auth method unmatched.");
        }
        return isMatched;
    }
}
