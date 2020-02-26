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
public interface ClientPolicyExecutor extends Provider {

    @Override
    default void close() {
    }

    /**
     * returns true if this executor is executed against the client.
     * A executor can be implemented to be executed on some events while not on others.
     * On the event specified as the parameter, this executor is skipped if this method returns false.
     *
     * @param event defined in {@link ClientPolicyEvent}
     * @return true if this executor is executed on the event.
     */
    default boolean isExecutedOnEvent(String event) {return true;}

    /**
     * execute actions against the client
     * on Dynamic Registration Endpoint access for creating client.
     *
     * @param context
     * @param authType
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType)  throws ClientPolicyException {}

    /**
     * execute actions against the client
     * on Dynamic Registration Endpoint access for updating client.
     *
     * @param context
     * @param authType
     * @param client - current client's model
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client)  throws ClientPolicyException {}

    /**
     * execute actions against the client
     * on Admin REST API Registration access for creating client.
     *
     * @param rep - client's representation to be created
     * @param admin - authenticated administrator's info
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) throws ClientPolicyException {};

    /**
     * execute actions against the client
     * on Admin REST API Registration access for updating client.
     *
     * @param rep - client's representation to be updated
     * @param admin - authenticated administrator's info
     * @param client - current client's model
     * @throws {@link ClientPolicyException} - if something wrong happens when execution actions
     */
    default void executeOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) throws ClientPolicyException {};

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
