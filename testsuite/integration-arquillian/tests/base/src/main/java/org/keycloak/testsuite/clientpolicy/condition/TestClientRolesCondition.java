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

import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;

public class TestClientRolesCondition implements ClientPolicyCondition {

    private static final Logger logger = Logger.getLogger(TestClientRolesCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public TestClientRolesCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public boolean isEvaluatedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.AUTHORIZATION_REQUEST:
            case ClientPolicyEvent.TOKEN_REQUEST:
            case ClientPolicyEvent.TOKEN_REFRESH:
            case ClientPolicyEvent.TOKEN_REVOKE:
            case ClientPolicyEvent.TOKEN_INTROSPECT:
            case ClientPolicyEvent.USERINFO_REQUEST:
            case ClientPolicyEvent.LOGOUT_REQUEST:
                return true;
        }
        return false;
    }

    // on Authorization Endpoint access for authorization request
    @Override
    public boolean isSatisfiedOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) {
        return isRolesMatched(session.getContext().getClient());
    }

    // on Token Endpoint access for token request
    @Override
    public boolean isSatisfiedOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) {
        return isRolesMatched(session.getContext().getClient());
    }

    // on Token Endpoint access for token refresh
    @Override
    public boolean isSatisfiedOnTokenRefresh(
            MultivaluedMap<String, String> params) {
        return isRolesMatched(session.getContext().getClient());
    }

    // on Token Revocation Endpoint access for token revoke
    @Override
    public boolean isSatisfiedOnTokenRevoke(
            MultivaluedMap<String, String> params) {
        return isRolesMatched(session.getContext().getClient());
    }

    // on Token Introspenction Endpoint access for token introspect
    @Override
    public boolean isSatisfiedOnTokenIntrospect(
            MultivaluedMap<String, String> params) {
        return isRolesMatched(session.getContext().getClient());
    }

    // on UserInfo Endpoint access for userinfo request
    @Override
    public boolean isSatisfiedOnUserInfoRequest(
            MultivaluedMap<String, String> params) {
        return isRolesMatched(session.getContext().getClient());
    }

    // on Logout Endpoint access for logout request
    @Override
    public boolean isSatisfiedOnLogoutRequest(
            MultivaluedMap<String, String> params) {
        return isRolesMatched(session.getContext().getClient());
    }

    private boolean isRolesMatched(ClientModel client) {
        if (client == null) return false;

        List<String> rolesForMatching = getRolesForMatching();
        if (rolesForMatching == null) return false;

        client.getRoles().stream().forEach(i -> ClientPolicyLogger.log(logger, "client role = " + i.getName()));
        rolesForMatching.stream().forEach(i -> ClientPolicyLogger.log(logger, "roles expected = " + i));

        boolean isMatched = rolesForMatching.stream().anyMatch(i->client.getRoles().stream().anyMatch(j->j.getName().equals(i)));
        if (isMatched) {
            ClientPolicyLogger.log(logger, "role matched.");
        } else {
            ClientPolicyLogger.log(logger, "role unmatched.");
        }
        return isMatched;
    }

    private List<String> getRolesForMatching() {
        return componentModel.getConfig().get(TestClientRolesConditionFactory.ROLES);
    }
}
