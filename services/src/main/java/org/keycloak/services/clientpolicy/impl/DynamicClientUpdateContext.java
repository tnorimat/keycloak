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

import org.keycloak.models.ClientModel;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class DynamicClientUpdateContext implements ClientUpdateContext {

    private final ClientRegistrationContext context;
    private final RegistrationAuth authType;
    private final ClientModel client;

    public DynamicClientUpdateContext(ClientRegistrationContext context,
            RegistrationAuth authType, ClientModel client) {
        this.context = context;
        this.authType = authType;
        this.client = client;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.DYNAMIC_UPDATE;
    }

    @Override
    public ClientRegistrationContext getDynamicClientRegistrationContext() {
        return context;
    }

    @Override
    public RegistrationAuth getDynamicRegistrationAuth() {
        return authType;
    }

    @Override
    public ClientModel getCurrentClientModel() {
        return client;
    }

}
