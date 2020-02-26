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

package org.keycloak.services.clientpolicy.executor.impl;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

/**
 * Executor can override the client settings to enforce some actions.
 * This feature can be activated or deactivated.
 */
public abstract class AbstractClientPoicyExecutor implements ClientPolicyExecutor {

    protected static final Logger logger = Logger.getLogger(AbstractClientPoicyExecutor.class);

    protected final KeycloakSession session;
    protected final ComponentModel componentModel;

    public AbstractClientPoicyExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    // on Dynamic Registration Endpoint access for creating client
    @Override
    public void executeOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) throws ClientPolicyException {
        if(isAugmentRequired()) augment(context.getClient());
        validate(context.getClient());
    }

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public void executeOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client)  throws ClientPolicyException {
        if(isAugmentRequired()) augment(context.getClient());
        validate(context.getClient());
    }
 
    // on Admin REST API Registration access for creating client
    @Override
    public void executeOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) throws ClientPolicyException {
        if(isAugmentRequired()) augment(rep);
        validate(rep);
    };

    // on Admin REST API Registration access for updating client
    @Override
    public void executeOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) throws ClientPolicyException {
        if(isAugmentRequired()) augment(rep);
        validate(rep);
    };

    /**
     * returns true if this executor overrides the client settings. 
     *
     * @return true if this executor overrides the client settings
     */
    protected abstract boolean isAugmentRequired();

    /**
     * overrides the client settings specified by the argument.
     *
     * @param rep - the client settings
     */
    protected abstract void augment(ClientRepresentation rep);

    /**
     * validate the client settings specified by the argument to check
     * whether they follows what the executor expects.
     *
     * @param rep - the client settings
     */
    protected abstract void validate(ClientRepresentation rep) throws ClientPolicyException;

}
