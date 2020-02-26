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
import java.util.stream.Collectors;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyManager;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

public class ClientPolicyManager {

    private static final Logger logger = Logger.getLogger(ClientPolicyManager.class);

    // Dynamic Client Registration
    // delegate executions to the existing ClientRegistrationPolicyManager

    public static void triggerBeforeRegister(ClientRegistrationContext context, RegistrationAuth authType) throws ClientRegistrationPolicyException, ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Dynamic Registration Endpoint access for creating client");
        doPolicyOperaion(
                context.getSession(),
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.DYNAMIC_REGISTER),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnDynamicClientRegister(context, authType),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.DYNAMIC_REGISTER),
                (ClientPolicyExecutor executor) -> executor.executeOnDynamicClientRegister(context, authType)
        );
        ClientRegistrationPolicyManager.triggerBeforeRegister(context, authType);
    }

    public static void triggerBeforeUpdate(ClientRegistrationContext context, RegistrationAuth authType, ClientModel client) throws ClientRegistrationPolicyException, ClientPolicyException  {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Dynamic Registration Endpoint access for updating client");
        doPolicyOperaion(
                context.getSession(),
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.DYNAMIC_UPDATE),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnDynamicClientUpdate(context, authType, client),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.DYNAMIC_UPDATE),
                (ClientPolicyExecutor executor) -> executor.executeOnDynamicClientUpdate(context, authType, client)
        );
        ClientRegistrationPolicyManager.triggerBeforeUpdate(context, authType, client);
    }

    public static void triggerBeforeRegisterByAdmin(KeycloakSession session, ClientRepresentation rep, AdminAuth admin) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Admin REST API Registration access for creating client");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.ADMIN_REGISTER),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnClientRegister(rep, admin),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.ADMIN_REGISTER),
                (ClientPolicyExecutor executor) -> executor.executeOnClientRegister(rep, admin)
        );
    }

    public static void triggerBeforeUpdateByAdmin(KeycloakSession session, ClientRepresentation rep, AdminAuth admin, ClientModel client) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Admin REST API Registration access for updating client");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.ADMIN_UPDATE),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnClientUpdate(rep, admin, client),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.ADMIN_UPDATE),
                (ClientPolicyExecutor executor) -> executor.executeOnClientUpdate(rep, admin, client)
        );
    }

    public static void triggerOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri,
            KeycloakSession session) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Authorization Endpoint access for authorization request");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.AUTHORIZATION_REQUEST),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnAuthorizationRequest(parsedResponseType, request, redirectUri),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.AUTHORIZATION_REQUEST),
                (ClientPolicyExecutor executor) -> executor.executeOnAuthorizationRequest(parsedResponseType, request, redirectUri)
        );
    }

    public static void triggerOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult,
            KeycloakSession session) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Endpoint access for token request");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.TOKEN_REQUEST),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnTokenRequest(params, parseResult),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.TOKEN_REQUEST),
                (ClientPolicyExecutor executor) -> executor.executeOnTokenRequest(params, parseResult)
        );
    }

    public static void triggerOnTokenRefresh(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Endpoint access for token refresh");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.TOKEN_REFRESH),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnTokenRefresh(params),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.TOKEN_REFRESH),
                (ClientPolicyExecutor executor) -> executor.executeOnTokenRefresh(params)
        );
    }

    public static void triggerOnTokenRevoke(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Revocation Endpoint access for token revoke");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.TOKEN_REVOKE),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnTokenRevoke(params),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.TOKEN_REVOKE),
                (ClientPolicyExecutor executor) -> executor.executeOnTokenRevoke(params)
        );
    }

    public static void triggerOnTokenIntrospect(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Token Introspenction Endpoint access for token introspect");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.TOKEN_INTROSPECT),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnTokenIntrospect(params),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.TOKEN_INTROSPECT),
                (ClientPolicyExecutor executor) -> executor.executeOnTokenIntrospect(params)
        );
    }

    public static void triggerOnUserInfoRequest(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on UserInfo Endpoint access for userinfo request");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.USERINFO_REQUEST),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnUserInfoRequest(params),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.USERINFO_REQUEST),
                (ClientPolicyExecutor executor) -> executor.executeOnUserInfoRequest(params)
        );
    }

    public static void triggerOnLogoutRequest(
            MultivaluedMap<String, String> params,
            KeycloakSession session) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Client Policy Operation : on Logout Endpoint access for logout request");
        doPolicyOperaion(
                session,
                (ClientPolicyCondition condition) -> condition.isEvaluatedOnEvent(ClientPolicyEvent.LOGOUT_REQUEST),
                (ClientPolicyCondition condition) -> condition.isSatisfiedOnLogoutRequest(params),
                (ClientPolicyExecutor executor) -> executor.isExecutedOnEvent(ClientPolicyEvent.LOGOUT_REQUEST),
                (ClientPolicyExecutor executor) -> executor.executeOnLogoutRequest(params)
        );
    }

    private static void doPolicyOperaion(KeycloakSession session, 
            ClientConditionFilter conditionFilter, ClientConditionOperation condition,
            ClientExecutorFilter executorFilter, ClientExecutorOperation executor) throws ClientPolicyException {
        RealmModel realm = session.getContext().getRealm();
        List<ComponentModel> policyModels = realm.getComponents(realm.getId(), ClientPolicyProvider.class.getName());
        for (ComponentModel policyModel : policyModels) {
            ClientPolicyProvider policy = session.getProvider(ClientPolicyProvider.class, policyModel);
            ClientPolicyLogger.log(logger, "Policy Name = " + policyModel.getName());
            if (!isSatisfied(policy, session, conditionFilter, condition)) continue;
            execute(policy, session, executorFilter, executor);
        }
    }

    private static boolean isSatisfied(
            ClientPolicyProvider policy,
            KeycloakSession session,
            ClientConditionFilter filter,
            ClientConditionOperation op) throws ClientPolicyException {

        List<String> conditionIds = policy.getConditionIds();

        if (conditionIds == null || conditionIds.isEmpty()) {
            ClientPolicyLogger.log(logger, "NEGATIVE :: This policy is not applied. No condition registered.");
            return false;
        }

        List<ClientPolicyCondition> conditions = conditionIds.stream()
                .map(s -> {
                        ComponentModel conditionModel = session.getContext().getRealm().getComponent(s);
                        ClientPolicyLogger.log(logger, "Condition ID = " + s);
                        ClientPolicyLogger.log(logger, "Condition Name = " + conditionModel.getName());
                        ClientPolicyLogger.log(logger, "Condition Provider ID = " + conditionModel.getProviderId());
                        return session.getProvider(ClientPolicyCondition.class, conditionModel);
                    })
                .filter(t -> {
                        try {return filter.run(t);} catch (ClientPolicyException e) {
                            ClientPolicyLogger.log(logger, "NEGATIVE :: This policy is not applied. " + e);
                            return false;
                        }
                }).collect(Collectors.toList());

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
            ClientExecutorFilter filter,
            ClientExecutorOperation op) throws ClientPolicyException {

        List<String> executorIds = policy.getExecutorIds();

        if (executorIds == null || executorIds.isEmpty()) {
            ClientPolicyLogger.log(logger, "NEGATIVE :: This executor is not executed. No executor registered.");
            return;
        }

        List<ClientPolicyExecutor> executors = executorIds.stream()
                .map(s -> {
                        ComponentModel conditionModel = session.getContext().getRealm().getComponent(s);
                        ClientPolicyLogger.log(logger, "Executor ID = " + s);
                        ClientPolicyLogger.log(logger, "Executor Name = " + conditionModel.getName());
                        ClientPolicyLogger.log(logger, "Executor Provider ID = " + conditionModel.getProviderId());
                        return session.getProvider(ClientPolicyExecutor.class, conditionModel);
                    })
                .filter(t -> {
                        try {return filter.run(t);} catch (ClientPolicyException e) {
                            ClientPolicyLogger.log(logger, "NEGATIVE :: This executor is not executed. " + e);
                            return false;
                        }
                }).collect(Collectors.toList());

        if (executors == null || executors.isEmpty()) {
            ClientPolicyLogger.log(logger, "NEGATIVE :: This executor is not executed. No executor executable.");
            return;
        }

        for (ClientPolicyExecutor executor : executors) op.run(executor);

    }

    private interface ClientConditionFilter {
        boolean run(ClientPolicyCondition condition) throws ClientPolicyException;
    }

    private interface ClientConditionOperation {
        boolean run(ClientPolicyCondition condition) throws ClientPolicyException;
    }

    private interface ClientExecutorFilter {
        boolean run(ClientPolicyExecutor executor) throws ClientPolicyException;
    }

    private interface ClientExecutorOperation {
        void run(ClientPolicyExecutor executor) throws ClientPolicyException;
    }

}
