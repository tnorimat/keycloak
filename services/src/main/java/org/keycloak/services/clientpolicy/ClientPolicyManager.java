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

package org.keycloak.services.clientpolicy;

import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.common.Profile;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;


public class ClientPolicyManager {

    private static final Logger logger = Logger.getLogger(ClientPolicyManager.class);

    // Dynamic Client Registration
    // delegate executions to the existing ClientRegistrationPolicyManager

    public static void triggerBeforeClientUpdate(KeycloakSession session, ClientUpdateContext context) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : event = " + context.getEvent());
        doPolicyOperation(
                session,
                context.getEvent(),
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnClientUpdate(context),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnClientUpdate(context)
        );
    }

    public static void triggerOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri,
            KeycloakSession session) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Authorization Endpoint access for authorization request");
        doPolicyOperation(
                session,
                ClientPolicyEvent.AUTHORIZATION_REQUEST,
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnAuthorizationRequest(parsedResponseType, request, redirectUri),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnAuthorizationRequest(parsedResponseType, request, redirectUri)
        );
    }

    public static void triggerOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult,
            KeycloakSession session) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Endpoint access for token request");
        doPolicyOperation(
                session,
                ClientPolicyEvent.TOKEN_REQUEST,
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnTokenRequest(params, parseResult),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnTokenRequest(params, parseResult)
        );
    }

    public static void triggerOnTokenRefresh(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Endpoint access for token refresh");
        doPolicyOperation(
                session,
                ClientPolicyEvent.TOKEN_REFRESH,
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnTokenRefresh(params),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnTokenRefresh(params)
        );
    }

    public static void triggerOnTokenRevoke(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Revocation Endpoint access for token revoke");
        doPolicyOperation(
                session,
                ClientPolicyEvent.TOKEN_REVOKE,
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnTokenRevoke(params),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnTokenRevoke(params)
        );
    }

    public static void triggerOnTokenIntrospect(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Introspenction Endpoint access for token introspect");
        doPolicyOperation(
                session,
                ClientPolicyEvent.TOKEN_INTROSPECT,
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnTokenIntrospect(params),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnTokenIntrospect(params)
        );
    }

    public static void triggerOnUserInfoRequest(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : on UserInfo Endpoint access for userinfo request");
        doPolicyOperation(
                session,
                ClientPolicyEvent.USERINFO_REQUEST,
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnUserInfoRequest(params),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnUserInfoRequest(params)
        );
    }

    public static void triggerOnLogoutRequest(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Logout Endpoint access for logout request");
        doPolicyOperation(
                session,
                ClientPolicyEvent.LOGOUT_REQUEST,
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnLogoutRequest(params),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnLogoutRequest(params)
        );
    }

    private static void doPolicyOperation(KeycloakSession session, ClientPolicyEvent event, ClientConditionOperation condition, ClientExecutorOperation executor) throws ClientPolicyException {
        RealmModel realm = session.getContext().getRealm();
        List<ComponentModel> policyModels = realm.getComponents(realm.getId(), ClientPolicyProvider.class.getName());
        for (ComponentModel policyModel : policyModels) {
            ClientPolicyProvider policy = session.getProvider(ClientPolicyProvider.class, policyModel);
            ClientPolicyLogger.log(logger, "Policy Name = " + policyModel.getName());
            if (!isSatisfied(policy, session, event, condition)) continue;
            execute(policy, session, executor);
        }
    }

    private static boolean isSatisfied(
            ClientPolicyProvider policy,
            KeycloakSession session,
            ClientPolicyEvent event,
            ClientConditionOperation op) throws ClientPolicyException {

        List<ClientPolicyConditionProvider> conditions = policy.getConditions(event);

        if (conditions == null || conditions.isEmpty()) {
            ClientPolicyLogger.log(logger, "NEGATIVE :: This policy is not applied. No condition evalutated.");
            return false;
        }

        if (conditions.stream().anyMatch(t -> {
                    try {return !op.run(t);} catch (ClientPolicyException e) {
                        ClientPolicyLogger.log(logger, "NEGATIVE :: This policy is not applied. " + e);
                        return false;
                    }
            })) {
            ClientPolicyLogger.log(logger, "NEGATIVE :: This policy is not applied. Not all conditones satisfied.");
            return false;
        }

        ClientPolicyLogger.log(logger, "POSITIVE :: This policy is applied.");
        return true;
 
    }

    private static void execute(
            ClientPolicyProvider policy,
            KeycloakSession session,
            ClientExecutorOperation op) throws ClientPolicyException {

        List<ClientPolicyExecutorProvider> executors = policy.getExecutors();
        if (executors == null || executors.isEmpty()) {
            ClientPolicyLogger.log(logger, "NEGATIVE :: This executor is not executed. No executor executable.");
            return;
        }
        for (ClientPolicyExecutorProvider executor : executors) op.run(executor);

    }

    private interface ClientConditionOperation {
        boolean run(ClientPolicyConditionProvider condition) throws ClientPolicyException;
    }

    private interface ClientExecutorOperation {
        void run(ClientPolicyExecutorProvider executor) throws ClientPolicyException;
    }

}
