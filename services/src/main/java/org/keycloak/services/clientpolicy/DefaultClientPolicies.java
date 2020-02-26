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

import java.util.ArrayList;
import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientpolicy.condition.impl.AuthnMethodsConditionFactory;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientpolicy.executor.impl.PKCEEnforceExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureRedirectUriExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureSessionsExecutorFactory;
import org.keycloak.services.clientpolicy.impl.DefaultClientPolicyProviderFactory;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class DefaultClientPolicies {

    public static final String BUILTIN_POLICY_NAME = "builtin-client-policy";

    // provider type
    public static final String BUILTIN_TYPE = "builtin-type";  // edit not allowed
    public static final String ADHOC_TYPE = "adhoc-type";      // edit allowed

    public static final String CONDITIONS = "conditions";
    public static final String EXECUTORS = "executors";

    public static void addDefaultPolicies(RealmModel realm) {
        List<ComponentModel> policies = realm.getComponents(realm.getId(), ClientPolicyProvider.class.getName());
        // Probably an issue if admin removes all policies intentionally...
        if (policies == null ||policies.isEmpty()) {
            //addAnonymousPolicy(realm);
            //addAuthPolicy(realm);
            //addFAPIROPolicy(realm);
        }
    }

    private static void addAnonymousPolicy(RealmModel realm) {
        // create conditions
        ComponentModel model = createModelInstance("builtin-anon-" + AuthnMethodsConditionFactory.PROVIDER_ID, realm, AuthnMethodsConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), BUILTIN_TYPE);
        model.getConfig().putSingle(AuthnMethodsConditionFactory.AUTH_METHOD, RegistrationAuth.ANONYMOUS.name());
        String conditionId = model.getId();
        List<String> conditions = new ArrayList<String>();
        conditions.add(conditionId);
        realm.addComponentModel(model);

        // create executors
        model = createModelInstance("builtin-anon-" + PKCEEnforceExecutorFactory.PROVIDER_ID, realm, PKCEEnforceExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), BUILTIN_TYPE);
        String executorId = model.getId();
        List<String> executors = new ArrayList<String>();
        executors.add(executorId);
        realm.addComponentModel(model);

        // create policy
        model = createModelInstance(BUILTIN_POLICY_NAME + "-anonymous-reg", realm, DefaultClientPolicyProviderFactory.PROVIDER_ID, ClientPolicyProvider.class.getName(), BUILTIN_TYPE);
        // make policy include this condition and executor
        model.getConfig().put(CONDITIONS ,conditions);
        model.getConfig().put(EXECUTORS ,executors);
        realm.addComponentModel(model);
    }

    private static void addAuthPolicy(RealmModel realm) {
        // create conditions
        ComponentModel model = createModelInstance("builtin-auth-" + AuthnMethodsConditionFactory.PROVIDER_ID, realm, AuthnMethodsConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), BUILTIN_TYPE);
        model.getConfig().putSingle(AuthnMethodsConditionFactory.AUTH_METHOD, RegistrationAuth.AUTHENTICATED.name());
        String conditionId = model.getId();
        List<String> conditions = new ArrayList<String>();
        conditions.add(conditionId);
        realm.addComponentModel(model);

        // create executors
        model = createModelInstance("builtin-auth-" + PKCEEnforceExecutorFactory.PROVIDER_ID, realm, PKCEEnforceExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), BUILTIN_TYPE);
        String executorId = model.getId();
        List<String> executors = new ArrayList<String>();
        executors.add(executorId);
        realm.addComponentModel(model);

        // create policy
        model = createModelInstance(BUILTIN_POLICY_NAME + "-auth-reg", realm, DefaultClientPolicyProviderFactory.PROVIDER_ID, ClientPolicyProvider.class.getName(), BUILTIN_TYPE);
        // make policy include this condition and executor
        model.getConfig().put(CONDITIONS ,conditions);
        model.getConfig().put(EXECUTORS ,executors);
        realm.addComponentModel(model);
    }

    private static void addFAPIROPolicy(RealmModel realm) {
        // create conditions
        ComponentModel model = createModelInstance("builtin-fapiro-" + AuthnMethodsConditionFactory.PROVIDER_ID, realm, AuthnMethodsConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), BUILTIN_TYPE);
        model.getConfig().putSingle(AuthnMethodsConditionFactory.AUTH_METHOD, RegistrationAuth.ANONYMOUS.name());
        String conditionId = model.getId();
        List<String> conditions = new ArrayList<String>();
        conditions.add(conditionId);
        realm.addComponentModel(model);

        // create executors
        model = createModelInstance("builtin-fapiro-" + PKCEEnforceExecutorFactory.PROVIDER_ID, realm, PKCEEnforceExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), BUILTIN_TYPE);
        String executorId = model.getId();
        List<String> executors = new ArrayList<String>();
        executors.add(executorId);
        realm.addComponentModel(model);

        model = createModelInstance("builtin-fapiro-" + SecureRedirectUriExecutorFactory.PROVIDER_ID, realm, SecureRedirectUriExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), BUILTIN_TYPE);
        executorId = model.getId();
        executors = new ArrayList<String>();
        executors.add(executorId);
        realm.addComponentModel(model);

        model = createModelInstance("builtin-fapiro-" + SecureSessionsExecutorFactory.PROVIDER_ID, realm, SecureSessionsExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), BUILTIN_TYPE);
        executorId = model.getId();
        executors = new ArrayList<String>();
        executors.add(executorId);
        realm.addComponentModel(model);

        // create policy
        model = createModelInstance(BUILTIN_POLICY_NAME + "-fapiro", realm, DefaultClientPolicyProviderFactory.PROVIDER_ID, ClientPolicyProvider.class.getName(), BUILTIN_TYPE);
        // make policy include this condition and executor
        model.getConfig().put(CONDITIONS ,conditions);
        model.getConfig().put(EXECUTORS ,executors);
        realm.addComponentModel(model);
    }

    private static ComponentModel createModelInstance(String name, RealmModel realm, String providerId, String providerType, String policyType) {
        ComponentModel model = new ComponentModel();
        model.setId(KeycloakModelUtils.generateId());
        model.setName(name);
        model.setParentId(realm.getId());
        model.setProviderId(providerId);
        model.setProviderType(providerType);
        model.setSubType(policyType);
        return model;
    }
}
