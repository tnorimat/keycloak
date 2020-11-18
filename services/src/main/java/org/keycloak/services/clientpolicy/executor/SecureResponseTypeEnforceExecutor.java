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

package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.AuthorizationRequestContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;

public class SecureResponseTypeEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(SecureResponseTypeEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public SecureResponseTypeEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case AUTHORIZATION_REQUEST:
                AuthorizationRequestContext authorizationRequestContext = (AuthorizationRequestContext)context;
                executeOnAuthorizationRequest(authorizationRequestContext.getparsedResponseType(),
                    authorizationRequestContext.getAuthorizationEndpointRequest(),
                    authorizationRequestContext.getRedirectUri());
                return;
            default:
                return;
        }
    }

    public void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Authz Endpoint - authz request");

        if (parsedResponseType.hasResponseType(OIDCResponseType.CODE) && parsedResponseType.hasResponseType(OIDCResponseType.ID_TOKEN)) {
            ClientPolicyLogger.log(logger, "Passed.response_type = code id_token");
            return;
        }

        if (parsedResponseType.hasResponseType(OIDCResponseType.CODE) && parsedResponseType.hasResponseType(OIDCResponseType.ID_TOKEN) && parsedResponseType.hasResponseType(OIDCResponseType.TOKEN)) {
            ClientPolicyLogger.log(logger, "Passed.response_type = code id_token token");
            return;
        }

        ClientPolicyLogger.log(logger, "invalid response_type = " + parsedResponseType);
        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "invalid response_type");

    }

}
