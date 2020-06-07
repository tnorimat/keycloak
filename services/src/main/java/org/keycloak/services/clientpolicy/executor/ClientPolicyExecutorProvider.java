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

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.provider.Provider;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

/**
 * This executor specifies what action is executed on the client to which to which {@link ClientPolicyProvider} is adopted.
 * The executor can be executed on the events defined in {@link ClientPolicyEvent}.
 * It is sufficient for the implementer of this executor to implement methods in which they are interested
 * and {@link isEvaluatedOnEvent} method.
 */
public interface ClientPolicyExecutorProvider extends Provider {

    @Override
    default void close() {
    }

    /**
     * execute actions against the client
     * on the client registration/update by Dynamic Client Registration and Admin REST API.
     *
     * @param context - the context in the client registration/update by Dynamic Client Registration or Admin REST API.
     */
    default void executeOnClientUpdate(ClientUpdateContext context) throws ClientPolicyException {}

    /**
     * execute actions against the client
     * on Authorization Endpoint access for authorization request.
     *
     * @param parsedResponseType - parsed OAuth2's response_type parameter
     * @param request - parsed OAuth2's authorization request
     * @param redirectUri - OAuth2's redirect_uri parameter
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {}

    /**
     * execute actions against the client
     * on Token Endpoint access for token request.
     *
     * @param params - form parameters on Token Endpoint
     * @param parseResult - parsed OAuth2's code parameter
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) throws ClientPolicyException {};

    /**
     * execute actions against the client
     * on Token Endpoint access for token refresh.
     *
     * @param params - form parameters on Token Endpoint
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnTokenRefresh(
            MultivaluedMap<String, String> params) throws ClientPolicyException {};

    /**
     * execute actions against the client
     * on Token Revocation Endpoint access for token revoke.
     *
     * @param params - form parameters on TokenRevocation Endpoint
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnTokenRevoke(
            MultivaluedMap<String, String> params) throws ClientPolicyException {};

    /**
     * execute actions against the client
     * on Token Introspenction Endpoint access for token introspect.
     *
     * @param params - form parameters on TokenIntrospection Endpoint
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnTokenIntrospect(
            MultivaluedMap<String, String> params) throws ClientPolicyException {};

    /**
     * execute actions against the client
     * on UserInfo Endpoint access for userinfo request.
     *
     * @param params - form parameters on UserInfo Endpoint
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnUserInfoRequest(
            MultivaluedMap<String, String> params) throws ClientPolicyException {};

    /**
     * execute actions against the client
     * on Logout Endpoint access for logout request.
     *
     * @param params - form parameters on Logout Endpoint
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnLogoutRequest(
            MultivaluedMap<String, String> params) throws ClientPolicyException {};

}
