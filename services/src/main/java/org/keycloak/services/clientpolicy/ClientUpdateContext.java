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
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;

/**
 * Represents the context in the client registration/update by Dynamic Client Registration or Admin REST API.
 */
public interface ClientUpdateContext extends ClientPolicyContext {

    /**
     * returns {@link ClientRepresentation} for creating or updating the current client.
     *
     * @return {@link ClientRepresentation}
     */
    default ClientRepresentation getProposedClientRepresentation() {
        return null;
    }

    /**
     * returns {@link ClientModel} of the current client to be updated.
     *
     * @return {@link ClientModel}
     */
    default ClientModel getClientToBeUpdated() {
        return null;
    }

    /**
     * returns {@link UserModel} of the authenticated user.
     *
     * @return {@link UserModel}
     */
    default UserModel getAuthenticatedUser() {
        return null;
    }

    /**
     * returns {@link UserModel} of the authenticated client.
     *
     * @return {@link UserModel}
     */
    default ClientModel getAuthenticatedClient() {
        return null;
    }

    /**
     * @return the newly registered client {@link ClientModel}
     */
    default ClientModel getRegisteredClient() {
        return null;
    }

    /**
     * @return the updated client {@link ClientModel}
     */
    default ClientModel getClientUpdated() {
        return null;
    }

    /**
     * returns {@link JsonWebToken} of the token accompanied with registration/update client
     *
     * @return {@link JsonWebToken}
     */
    default JsonWebToken getToken() {
        return null;
    }

}
