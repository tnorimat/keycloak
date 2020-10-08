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

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.clientregistration.policy.impl.ClientScopesClientRegistrationPolicyFactory;

public class ClientScopesExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ClientScopesExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;
    private final RealmModel realm;

    public ClientScopesExecutor(KeycloakSession session, ComponentModel componentModel) {
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
            case REGISTER:
                clientUpdateContext = (ClientUpdateContext)context;
                beforeRegister(clientUpdateContext.getProposedClientRepresentation());
                break;
            case UPDATE:
                clientUpdateContext = (ClientUpdateContext)context;
                beforeUpdate(clientUpdateContext.getClientToBeUpdated(), clientUpdateContext.getProposedClientRepresentation());
                break;
            default:
                return;
        }
    }

    private void beforeRegister(ClientRepresentation proposedClient) throws ClientPolicyException {
        List<String> requestedDefaultScopeNames = proposedClient.getDefaultClientScopes();
        List<String> requestedOptionalScopeNames = proposedClient.getOptionalClientScopes();

        List<String> allowedDefaultScopeNames = getAllowedScopeNames(realm, true);
        List<String> allowedOptionalScopeNames = getAllowedScopeNames(realm, false);

        checkClientScopesAllowed(requestedDefaultScopeNames, allowedDefaultScopeNames);
        checkClientScopesAllowed(requestedOptionalScopeNames, allowedOptionalScopeNames);
    }

    private void beforeUpdate(ClientModel clientToBeUpdated, ClientRepresentation proposedClient) throws ClientPolicyException {
        List<String> requestedDefaultScopeNames = proposedClient.getDefaultClientScopes();
        List<String> requestedOptionalScopeNames = proposedClient.getOptionalClientScopes();

        // Allow scopes, which were already presented before
        if (requestedDefaultScopeNames != null) {
            requestedDefaultScopeNames.removeAll(clientToBeUpdated.getClientScopes(true, false).keySet());
        }
        if (requestedOptionalScopeNames != null) {
            requestedOptionalScopeNames.removeAll(clientToBeUpdated.getClientScopes(false, false).keySet());
        }

        List<String> allowedDefaultScopeNames = getAllowedScopeNames(realm, true);
        List<String> allowedOptionalScopeNames = getAllowedScopeNames(realm, false);

        checkClientScopesAllowed(requestedDefaultScopeNames, allowedDefaultScopeNames);
        checkClientScopesAllowed(requestedOptionalScopeNames, allowedOptionalScopeNames);
    }

    private void checkClientScopesAllowed(List<String> requestedScopes, List<String> allowedScopes) throws ClientPolicyException {
        if (requestedScopes != null) {
            for (String requested : requestedScopes) {
                if (!allowedScopes.contains(requested)) {
                    logger.warnf("Requested scope '%s' not trusted in the list: %s", requested, allowedScopes.toString());
                    throw new ClientPolicyException(Errors.INVALID_REGISTRATION, "Not permitted to use specified clientScope");
                }
            }
        }
    }

    private List<String> getAllowedScopeNames(RealmModel realm, boolean defaultScopes) {
        List<String> allAllowed = new LinkedList<>();

        // Add client scopes allowed by config
        List<String> allowedScopesConfig = componentModel.getConfig().getList(ClientScopesClientRegistrationPolicyFactory.ALLOWED_CLIENT_SCOPES);
        if (allowedScopesConfig != null) {
            allAllowed.addAll(allowedScopesConfig);
        }

        // If allowDefaultScopes, then realm default scopes are allowed as default scopes (+ optional scopes are allowed as optional scopes)
        boolean allowDefaultScopes = componentModel.get(ClientScopesClientRegistrationPolicyFactory.ALLOW_DEFAULT_SCOPES, true);
        if (allowDefaultScopes) {
            List<String> scopeNames = realm.getDefaultClientScopes(defaultScopes).stream().map((ClientScopeModel clientScope) -> {

                return clientScope.getName();

            }).collect(Collectors.toList());

            allAllowed.addAll(scopeNames);
        }

        return allAllowed;
    }

}
