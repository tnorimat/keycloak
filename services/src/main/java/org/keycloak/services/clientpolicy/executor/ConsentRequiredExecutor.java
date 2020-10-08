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

package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class ConsentRequiredExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ConsentRequiredExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;
    private final RealmModel realm;

    public ConsentRequiredExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
        this.realm = session.realms().getRealm(componentModel.getParentId());
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        ClientUpdateContext clientUpdateContext = null;
        switch (context.getEvent()) {
            case REGISTERED:
                clientUpdateContext = (ClientUpdateContext)context;
                afterRegister(clientUpdateContext.getRegisteredClient());
                break;
            case UPDATE:
                clientUpdateContext = (ClientUpdateContext)context;
                beforeUpdate(clientUpdateContext.getClientToBeUpdated(), clientUpdateContext.getProposedClientRepresentation());
                break;
            default:
                return;
        }
    }

    private void afterRegister(ClientModel clientModel) {
        clientModel.setConsentRequired(true);
    }

    public void beforeUpdate(ClientModel clientToBeUpdated, ClientRepresentation proposedClient) throws ClientPolicyException {
        if (proposedClient.isConsentRequired() == null) {
            return;
        }
        if (clientToBeUpdated == null) {
            return;
        }

        boolean isEnabled = clientToBeUpdated.isConsentRequired();
        boolean newEnabled = proposedClient.isConsentRequired();

        if (isEnabled && !newEnabled) {
            throw new ClientPolicyException(Errors.INVALID_REGISTRATION, "Not permitted to update consentRequired to false");
        }
    }

}
