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

package org.keycloak.services.clientpolicy.impl;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.common.Profile;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyManager;
import org.keycloak.services.clientpolicy.ClientPolicyProvider;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

public class DefaultClientPolicyManager implements ClientPolicyManager {

    private static final Logger logger = Logger.getLogger(DefaultClientPolicyManager.class);

    private final KeycloakSession session;

    public DefaultClientPolicyManager(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void triggerOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_POLICIES)) return;
        ClientPolicyLogger.log(logger, "Client Policy Operation : event = " + context.getEvent());
        doPolicyOperation(
                context.getEvent(),
                (ClientPolicyConditionProvider condition) -> condition.isSatisfiedOnEvent(context),
                (ClientPolicyExecutorProvider executor) -> executor.executeOnEvent(context)
        );
    }

    private void doPolicyOperation(ClientPolicyEvent event, ClientConditionOperation condition, ClientExecutorOperation executor) throws ClientPolicyException {
        RealmModel realm = session.getContext().getRealm();
        List<ComponentModel> policyModels = realm.getComponents(realm.getId(), ClientPolicyProvider.class.getName());
        for (ComponentModel policyModel : policyModels) {
            ClientPolicyProvider policy = session.getProvider(ClientPolicyProvider.class, policyModel);
            ClientPolicyLogger.log(logger, "Policy Name = " + policyModel.getName());
            if (!isSatisfied(policy, event, condition)) continue;
            execute(policy, executor);
        }
    }

    private boolean isSatisfied(
            ClientPolicyProvider policy,
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

    private void execute(
            ClientPolicyProvider policy,
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
