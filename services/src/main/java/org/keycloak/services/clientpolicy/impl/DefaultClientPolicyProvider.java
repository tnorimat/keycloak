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
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyProvider;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

public class DefaultClientPolicyProvider implements ClientPolicyProvider {

    private static final Logger logger = Logger.getLogger(DefaultClientPolicyProvider.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public DefaultClientPolicyProvider(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }
 
    @Override
    public void close() {
    }

    @Override
    public List<ClientPolicyConditionProvider> getConditions() {
        List<String> conditionIds = getConditionIds();

        if (conditionIds == null || conditionIds.isEmpty()) return null;

        List<ClientPolicyConditionProvider> conditions = conditionIds.stream()
                .map(s -> {
                        ComponentModel cm = session.getContext().getRealm().getComponent(s);
                        ClientPolicyLogger.log(logger, new StringBuffer().append("Condition ID = ").append(s).append(", Condition Name = ").append(cm.getName()).append(", Condition Provider ID = ").append(cm.getProviderId()).toString());
                        return session.getProvider(ClientPolicyConditionProvider.class, cm);
                    }).collect(Collectors.toList());

        return conditions;
    }

    @Override
    public List<ClientPolicyConditionProvider> getConditions(ClientPolicyEvent event) {
        List<String> conditionIds = getConditionIds();

        if (conditionIds == null || conditionIds.isEmpty()) return null;
        List<ClientPolicyConditionProvider> conditions = conditionIds.stream()
                .map(s -> {
                        ComponentModel cm = session.getContext().getRealm().getComponent(s);
                        ClientPolicyLogger.log(logger, new StringBuffer().append("Condition ID = ").append(s).append(", Condition Name = ").append(cm.getName()).append(", Condition Provider ID = ").append(cm.getProviderId()).toString());
                        return session.getProvider(ClientPolicyConditionProvider.class, cm);
                    }).filter(t -> t.isEvaluatedOnEvent(event)).collect(Collectors.toList());

        return conditions;
    }

    @Override
    public List<ClientPolicyExecutorProvider> getExecutors() {
        List<String> executorIds = getExecutorIds();

        if (executorIds == null || executorIds.isEmpty()) return null;

        List<ClientPolicyExecutorProvider> executors = executorIds.stream()
                .map(s -> {
                        ComponentModel cm = session.getContext().getRealm().getComponent(s);
                        ClientPolicyLogger.log(logger, new StringBuffer().append("Executor ID = ").append(s).append(", Executor Name = ").append(cm.getName()).append(", Executor Provider ID = ").append(cm.getProviderId()).toString());
                        return session.getProvider(ClientPolicyExecutorProvider.class, cm);
                    }).collect(Collectors.toList());
 
        return executors;
    }

    private List<String> getConditionIds() {
        return componentModel.getConfig().getList(DefaultClientPolicyProviderFactory.CONDITION_IDS);
    }

    private List<String> getExecutorIds() {
        return componentModel.getConfig().getList(DefaultClientPolicyProviderFactory.EXECUTOR_IDS);
    }

}
