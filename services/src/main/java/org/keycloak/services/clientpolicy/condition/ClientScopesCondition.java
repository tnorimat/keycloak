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

package org.keycloak.services.clientpolicy.condition;

import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.services.clientpolicy.AuthorizationRequestContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.ClientPolicyVote;

public class ClientScopesCondition implements ClientPolicyConditionProvider {

    private static final Logger logger = Logger.getLogger(ClientScopesCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientScopesCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public ClientPolicyVote applyPolicy(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case AUTHORIZATION_REQUEST:
                if (isScopeMatched(((AuthorizationRequestContext)context).getAuthorizationEndpointRequest())) return ClientPolicyVote.YES;
                return ClientPolicyVote.NO;
            case TOKEN_REQUEST:
            case TOKEN_REFRESH:
            case TOKEN_REVOKE:
            case TOKEN_INTROSPECT:
            case USERINFO_REQUEST:
            case LOGOUT_REQUEST:
                if (isScopeMatched(session.getContext().getClient())) return ClientPolicyVote.YES;
                return ClientPolicyVote.NO;
            default:
                return ClientPolicyVote.ABSTAIN;
        }
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    private boolean isScopeMatched(AuthorizationEndpointRequest request) {
        if (request == null) return false;

        Set<ClientScopeModel> scopes = TokenManager.getRequestedClientScopes(request.getScope(), session.getContext().getRealm().getClientByClientId(request.getClientId()));

        boolean isMatched = componentModel.getConfig().get(ClientScopesConditionFactory.SCOPES).stream().anyMatch(i->{
            return scopes.stream().anyMatch(j->j.getName().equals(i));
            });
        if (isMatched) {
            ClientPolicyLogger.log(logger, "scope matched.");
        } else {
            ClientPolicyLogger.log(logger, "scope unmatched.");
        }
        return isMatched;
    }

    private boolean isScopeMatched(ClientModel client) {
        if (client == null) return false;

        client.getClientScopes(true, true).keySet().stream().forEach(i -> ClientPolicyLogger.log(logger, " default client scope = " + i));
        client.getClientScopes(false, true).keySet().stream().forEach(i -> ClientPolicyLogger.log(logger, " optional client scope = " + i));
        componentModel.getConfig().get(ClientScopesConditionFactory.SCOPES).stream().forEach(i -> ClientPolicyLogger.log(logger, "scope expected = " + i));

        boolean isDefaultScope = ClientScopesConditionFactory.DEFAULT.equals(componentModel.getConfig().getFirst(ClientScopesConditionFactory.TYPE));
        boolean isMatched = componentModel.getConfig().get(ClientScopesConditionFactory.SCOPES).stream().anyMatch(i->{
                return client.getClientScopes(isDefaultScope, true).keySet().stream().anyMatch(j->j.equals(i));
                });
        if (isMatched) {
            ClientPolicyLogger.log(logger, "scope matched.");
        } else {
            ClientPolicyLogger.log(logger, "scope unmatched.");
        }
        return isMatched;
    }

}
