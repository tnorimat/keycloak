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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.AdminClientRegisterContext;
import org.keycloak.services.clientpolicy.AdminClientUpdateContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.DynamicClientRegisterContext;
import org.keycloak.services.clientpolicy.DynamicClientUpdateContext;

public class SecureSigningAlgorithmEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(SecureSigningAlgorithmEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public SecureSigningAlgorithmEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
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
        case REGISTER:
            if (context instanceof AdminClientRegisterContext) {
                verifySecureSigningAlgorithmOnRegistration(((AdminClientRegisterContext)context).getProposedClientRepresentation(), true);
            } else if (context instanceof DynamicClientRegisterContext) {
                verifySecureSigningAlgorithmOnRegistration(((DynamicClientRegisterContext)context).getProposedClientRepresentation(), false);
            } else {
                throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed input format.");
            }
            break;
        case UPDATE:
            if (context instanceof AdminClientUpdateContext) {
                verifySecureSigningAlgorithmOnUpdate(((AdminClientUpdateContext)context).getProposedClientRepresentation(), true);
            } else if (context instanceof DynamicClientUpdateContext) {
                verifySecureSigningAlgorithmOnUpdate(((DynamicClientUpdateContext)context).getProposedClientRepresentation(), false);
            } else {
                throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed input format.");
            }
            break;
        default:
            return;
        }
    }

    private void verifySecureSigningAlgorithmOnRegistration(ClientRepresentation clientRep, boolean isAdminUpdate) throws ClientPolicyException {

        if (clientRep.getAttributes() == null) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "no signature algorithm was specified.");
        }

        Map<String, String> sigAlgsMap = new HashMap<>();
        sigAlgsMap.put("User Info", clientRep.getAttributes().get(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG));
        sigAlgsMap.put("Request Object", clientRep.getAttributes().get(OIDCConfigAttributes.REQUEST_OBJECT_SIGNATURE_ALG));
        sigAlgsMap.put("ID Token", clientRep.getAttributes().get(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG));
        sigAlgsMap.put("Token Endpoint Signing", clientRep.getAttributes().get(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG));

        for (String sigAlgKey : sigAlgsMap.keySet()) {
            ClientPolicyLogger.log(logger, sigAlgKey);
            verifySecureSigningAlgorithm(sigAlgsMap.get(sigAlgKey));
        }

        // no client metadata found in RFC 7591 OAuth Dynamic Client Registration Metadata
        if (isAdminUpdate) {
            String sigAlg = clientRep.getAttributes().get(OIDCConfigAttributes.ACCESS_TOKEN_SIGNED_RESPONSE_ALG);
            verifySecureSigningAlgorithm(sigAlg);
        }
    }

    private void verifySecureSigningAlgorithmOnUpdate(ClientRepresentation clientRep, boolean isAdminUpdate) throws ClientPolicyException {

        if (clientRep.getAttributes() == null) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "no signature algorithm was specified.");
        }

        Map<String, String> sigAlgsMap = new HashMap<>();
        String sigAlg = clientRep.getAttributes().get(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG);
        if (sigAlg != null) sigAlgsMap.put("User Info", sigAlg);
        sigAlg = clientRep.getAttributes().get(OIDCConfigAttributes.REQUEST_OBJECT_SIGNATURE_ALG);
        if (sigAlg != null) sigAlgsMap.put("Request Object", sigAlg);
        sigAlg = clientRep.getAttributes().get(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG);
        if (sigAlg != null) sigAlgsMap.put("ID Token", sigAlg);
        sigAlg = clientRep.getAttributes().get(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
        if (sigAlg != null) sigAlgsMap.put("Token Endpoint Signing", sigAlg);

        for (String sigAlgKey : sigAlgsMap.keySet()) {
            ClientPolicyLogger.log(logger, sigAlgKey);
            verifySecureSigningAlgorithm(sigAlgsMap.get(sigAlgKey));
        }

        // no client metadata found in RFC 7591 OAuth Dynamic Client Registration Metadata
        if (isAdminUpdate) {
            sigAlg = clientRep.getAttributes().get(OIDCConfigAttributes.ACCESS_TOKEN_SIGNED_RESPONSE_ALG);
            if (sigAlg != null)  verifySecureSigningAlgorithm(sigAlg);
        }

    }

    private void verifySecureSigningAlgorithm(String signatureAlgorithm) throws ClientPolicyException {
        if (signatureAlgorithm == null) {
            ClientPolicyLogger.log(logger, "Signing algorithm not specified explicitly.");
            return;
        }
        switch (signatureAlgorithm) {
        case Algorithm.PS256:
        case Algorithm.PS384:
        case Algorithm.PS512:
        case Algorithm.ES256:
        case Algorithm.ES384:
        case Algorithm.ES512:
            ClientPolicyLogger.log(logger, "Passed. signatureAlgorithm = " + signatureAlgorithm);
            return;
        }
        ClientPolicyLogger.log(logger, "NOT allowed signatureAlgorithm = " + signatureAlgorithm);
        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed signature algorithm.");
    }

}
