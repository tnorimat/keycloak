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

package org.keycloak.services.clientpolicy.condition;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.provider.Provider;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.resources.admin.AdminAuth;

/**
 * This condition determines to which client a {@link ClientPolicyProvider} is adopted.
 * The condition can be evaluated on the events defined in {@link ClientPolicyEvent}.
 * It is sufficient for the implementer of this condition to implement methods in which they are interested
 * and {@link isEvaluatedOnEvent} method.
 */
public interface ClientPolicyCondition extends Provider {

    @Override
    default void close() {}

    /**
     * returns true if this condition is evaluated to check
     * whether the client satisfies this condition on the event specified as a parameter.
     * A condition can be implemented to be evaluated on some events while not on others.
     * On the event specified as the parameter, this condition is skipped if this method returns false.
     *
     * @param event defined in {@link ClientPolicyEvent}
     * @return true if this condition is evaluated on the event.
     */
    default boolean isEvaluatedOnEvent(String event) {return true;}

    /**
     * returns true if the client satisfies this condition
     * on Dynamic Registration Endpoint access for creating client.
     *
     * @param context
     * @param authType
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) {return true;};

    /**
     * returns true if the client satisfies this condition
     * on Dynamic Registration Endpoint access for updating client.
     *
     * @param context
     * @param authType
     * @param client - current client's model
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client) {return true;};

    /**
     * returns true if the client satisfies this condition
     * on Admin REST API Registration access for creating client.
     *
     * @param rep - client's representation to be created
     * @param admin - authenticated administrator's info
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnClientRegister(
            ClientRepresentation rep,
            AdminAuth admin) {return true;};
 
    /**
     * returns true if the client satisfies this condition
     * on Admin REST API Registration access for updating client.
     *
     * @param rep - client's representation to be updated
     * @param admin - authenticated administrator's info
     * @param client - current client's model
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnClientUpdate(
            ClientRepresentation rep,
            AdminAuth admin,
            ClientModel client) {return true;};

    /**
     * returns true if the client satisfies this condition
     * on Authorization Endpoint access for authorization request.
     *
     * @param parsedResponseType - parsed OAuth2's response_type parameter
     * @param request - parsed OAuth2's authorization request
     * @param redirectUri - OAuth2's redirect_uri parameter
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) {return true;}

    /**
     * returns true if the client satisfies this condition
     * on Token Endpoint access for token request.
     *
     * @param params - form parameters on Token Endpoint
     * @param parseResult - parsed OAuth2's code parameter
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) {return true;}

    /**
     * returns true if the client satisfies this condition
     * on Token Endpoint access for token refresh.
     *
     * @param params - form parameters on Token Endpoint
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnTokenRefresh(
            MultivaluedMap<String, String> params) {return true;}

    /**
     * returns true if the client satisfies this condition
     * on Token Revocation Endpoint access for token revoke.
     *
     * @param params - form parameters on TokenRevocation Endpoint
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnTokenRevoke(
            MultivaluedMap<String, String> params) {return true;}

    /**
     * returns true if the client satisfies this condition
     * on Token Introspenction Endpoint access for token introspect.
     *
     * @param params - form parameters on TokenIntrospection Endpoint
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnTokenIntrospect(
            MultivaluedMap<String, String> params) {return true;}

    /**
     * returns true if the client satisfies this condition
     * on UserInfo Endpoint access for userinfo request.
     *
     * @param params - form parameters on UserInfo Endpoint
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnUserInfoRequest(
            MultivaluedMap<String, String> params) {return true;}

    /**
     * returns true if the client satisfies this condition
     * on Logout Endpoint access for logout request.
     *
     * @param params - form parameters on Logout Endpoint
     * @return true if the client satisfies this condition.
     */
    default boolean isSatisfiedOnLogoutRequest(
            MultivaluedMap<String, String> params) {return true;}
}
