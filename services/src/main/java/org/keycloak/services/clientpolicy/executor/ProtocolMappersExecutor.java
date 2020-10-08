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

import java.util.List;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class ProtocolMappersExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(MaxClientsExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ProtocolMappersExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
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
            case REGISTER:
                clientUpdateContext = (ClientUpdateContext)context;
                beforeRegister(clientUpdateContext.getProposedClientRepresentation());
            break;
            case REGISTERED:
                clientUpdateContext = (ClientUpdateContext)context;
                afterRegister(clientUpdateContext.getRegisteredClient());
                break;
            case UPDATE:
                clientUpdateContext = (ClientUpdateContext)context;
                beforeUpdate(clientUpdateContext.getProposedClientRepresentation());
                break;
            default:
                return;
        }
    }

    private void beforeRegister(ClientRepresentation client) throws ClientPolicyException {
        testMappers(client);
    }

    // Remove builtin mappers of unsupported types too
    public void afterRegister(ClientModel clientModel) {
        // Remove mappers of unsupported type, which were added "automatically"
        List<String> allowedMapperProviders = getAllowedMapperProviders();
        Set<ProtocolMapperModel> createdMappers = clientModel.getProtocolMappers();

        createdMappers.stream().filter((ProtocolMapperModel mapper) -> {

            return !allowedMapperProviders.contains(mapper.getProtocolMapper());

        }).forEach((ProtocolMapperModel mapperToRemove) -> {

            logger.debugf("Removing builtin mapper '%s' of type '%s' as type is not permitted", mapperToRemove.getName(), mapperToRemove.getProtocolMapper());
            clientModel.removeProtocolMapper(mapperToRemove);

        });

    }

    // We don't take already existing protocolMappers into consideration for now
    public void beforeUpdate(ClientRepresentation client) throws ClientPolicyException {
        testMappers(client);
    }

    private void testMappers(ClientRepresentation client) throws ClientPolicyException {
        List<ProtocolMapperRepresentation> protocolMappers = client.getProtocolMappers();
        if (protocolMappers == null) {
            return;
        }

        List<String> allowedMapperProviders = getAllowedMapperProviders();

        for (ProtocolMapperRepresentation mapper : protocolMappers) {
            String mapperType = mapper.getProtocolMapper();

            if (!allowedMapperProviders.contains(mapperType)) {
                ServicesLogger.LOGGER.clientRegistrationMapperNotAllowed(mapper.getName(), mapperType);
                throw new ClientPolicyException(Errors.INVALID_REGISTRATION, "ProtocolMapper type not allowed");
            }
        }
    }

    private List<String> getAllowedMapperProviders() {
        return componentModel.getConfig().getList(ProtocolMappersExecutorFactory.ALLOWED_PROTOCOL_MAPPER_TYPES);
    }
}
