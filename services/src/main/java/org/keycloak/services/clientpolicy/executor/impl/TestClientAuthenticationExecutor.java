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

package org.keycloak.services.clientpolicy.executor.impl;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.AbstractClientPoicyExecutor;

public class TestClientAuthenticationExecutor extends AbstractClientPoicyExecutor {

    private static final Logger logger = Logger.getLogger(TestClientAuthenticationExecutor.class);

    public TestClientAuthenticationExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.DYNAMIC_UPDATE:
            case ClientPolicyEvent.ADMIN_REGISTER:
            case ClientPolicyEvent.ADMIN_UPDATE:
                return true;
        }
        return false;
    }

    protected boolean isAugmentRequired() {
        return Boolean.valueOf(componentModel.getConfig().getFirst(ClientPolicyExecutorFactory.IS_AUGMENT));
    }

    protected void augment(ClientRepresentation rep) {
        rep.setClientAuthenticatorType(enforcedClientAuthenticatorType());
    }

    protected void validate(ClientRepresentation rep) throws ClientPolicyException {
        verifyClientAuthenticationMethod(rep.getClientAuthenticatorType());
    }

    private String enforcedClientAuthenticatorType() {
        return componentModel.getConfig().getFirst(TestClientAuthenticationExecutorFactory.CLIENT_AUTHNS_AUGMENT);
    }

    private void verifyClientAuthenticationMethod(String clientAuthenticatorType) throws ClientPolicyException {
        List<String> acceptableClientAuthn = componentModel.getConfig().getList(TestClientAuthenticationExecutorFactory.CLIENT_AUTHNS);
        if (acceptableClientAuthn != null && acceptableClientAuthn.stream().anyMatch(i->i.equals(clientAuthenticatorType))) return;
        throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: token_endpoint_auth_method");
    }
}
