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

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.util.MtlsHoKTokenUtil;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class HolderOfKeyEnforceExecutor extends AbstractAugumentingClientRegistrationPolicyExecutor {

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    private boolean useMtlsHokToken;

    public HolderOfKeyEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
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
    protected void augment(ClientRepresentation rep) {
        if (Boolean.parseBoolean(componentModel.getConfig().getFirst(AbstractAugumentingClientRegistrationPolicyExecutor.IS_AUGMENT))) {
            OIDCAdvancedConfigWrapper.fromClientRepresentation(rep).setUseMtlsHoKToken(true);
        }
    }

    @Override
    protected void validate(ClientRepresentation rep) throws ClientPolicyException {
        useMtlsHokToken = OIDCAdvancedConfigWrapper.fromClientRepresentation(rep).isUseMtlsHokToken();
        if (!useMtlsHokToken) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: MTLS token in disabled");
        }
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        super.executeOnEvent(context);
        HttpRequest request = session.getContext().getContextObject(HttpRequest.class);

        switch (context.getEvent()) {

            case TOKEN_REQUEST:
                if (useMtlsHokToken) {
                    AccessToken.CertConf certConf = MtlsHoKTokenUtil.bindTokenWithClientCertificate(request, session);
                    if (certConf == null) {
                        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Client Certification missing for MTLS HoK Token Binding");
                    }
                }
                break;

            case TOKEN_REFRESH:
            case TOKEN_REVOKE:
            case USERINFO_REQUEST:
            case LOGOUT_REQUEST:
                if (useMtlsHokToken) {
                    String clientAssertion = request.getDecodedFormParameters().getFirst(OAuth2Constants.CLIENT_ASSERTION);
                    JWSInput jws;
                    try {
                        jws = new JWSInput(clientAssertion);
                    } catch (JWSInputException e) {
                        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Cannot parse JWT token");
                    }

                    AccessToken token;

                    try {
                        token = JsonSerialization.readValue(jws.getContent(), AccessToken.class);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    if (!MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, request, session)) {
                        throw new ClientPolicyException(Errors.NOT_ALLOWED, MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC);
                    }
                }
        }
    }

}
