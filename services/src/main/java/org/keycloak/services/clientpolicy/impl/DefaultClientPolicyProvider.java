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
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyProvider;

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
    public List<String> getConditionIds() {
        return componentModel.getConfig().getList(DefaultClientPolicyProviderFactory.CONDITION_IDS);
    }

    @Override
    public List<String> getExecutorIds() {
        return componentModel.getConfig().getList(DefaultClientPolicyProviderFactory.EXECUTOR_IDS);
    }

}
