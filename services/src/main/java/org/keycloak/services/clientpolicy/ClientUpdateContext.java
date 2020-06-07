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

import org.keycloak.models.ClientModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

/**
 * Represents the context in the client registration/update by Dynamic Client Registration or Admin REST API.
 */
public interface ClientUpdateContext {

    /**
     * returns {@link ClientPolicyEvent} in this client registration/update context.
     * 
     * @return {@link ClientPolicyEvent}
     */
    ClientPolicyEvent getEvent();

    /**
     * returns {@link ClientModel} of the current client that will be updated.
     *
     * @return {@link ClientModel}
     */
    default ClientModel getCurrentClientModel() {return null;}

    /**
     * returns {@link ClientRepresentation} for updating the current client by Admin REST API.
     *
     * @return {@link ClientRepresentation}
     */
    default ClientRepresentation getProposedClientRepresentation() {return null;}

    /**
     * returns {@link RegistrationAuth} by Dynamic Client Registration.
     *
     * @return {@link RegistrationAuth}
     */
    default RegistrationAuth getDynamicRegistrationAuth() {return null;}

    /**
     * returns {@link AdminAuth} by Admin REST API.
     *
     * @return {@link AdminAuth}
     */
    default AdminAuth getAdminAuth() {return null;}

    /**
     * returns {@link ClientRegistrationContext} by Dynamic Client Registration.
     *
     * @return {@link ClientRegistrationContext}
     */
    default ClientRegistrationContext getDynamicClientRegistrationContext() {return null;}

}
