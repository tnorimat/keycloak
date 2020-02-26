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

package org.keycloak.testsuite.clientpolicy.condition;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

public class TestAuthnMethodsCondition implements ClientPolicyCondition {

    private static final Logger logger = Logger.getLogger(TestAuthnMethodsCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public TestAuthnMethodsCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public boolean isEvaluatedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.DYNAMIC_UPDATE:
            case ClientPolicyEvent.ADMIN_REGISTER:
            case ClientPolicyEvent.ADMIN_UPDATE:
                return true;
        }
        return false;
    }

    // on Dynamic Registration Endpoint access for creating client
    @Override
    public boolean isSatisfiedOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) {
        return authType == null ? false : isAuthMethodMatched(authType.name());
    }

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public boolean isSatisfiedOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client) {
        return authType == null ? false : isAuthMethodMatched(authType.name());
    }

    // on Admin REST API Registration access for creating client
    @Override
    public boolean isSatisfiedOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) {
        return isAuthMethodMatched(TestAuthnMethodsConditionFactory.BY_ADMIN_REST_API);
    };

    // on Admin REST API Registration access for updating client
    @Override
    public boolean isSatisfiedOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) {
        return isAuthMethodMatched(TestAuthnMethodsConditionFactory.BY_ADMIN_REST_API);
    };

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
