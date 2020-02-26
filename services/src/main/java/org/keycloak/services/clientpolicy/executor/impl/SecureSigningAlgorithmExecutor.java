package org.keycloak.services.clientpolicy.executor.impl;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;

public class SecureSigningAlgorithmExecutor extends AbstractObsoleteClientPolicyExecutor {
    private static final Logger logger = Logger.getLogger(SecureSigningAlgorithmExecutor.class);

    public SecureSigningAlgorithmExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.DYNAMIC_REGISTER:
            case ClientPolicyEvent.DYNAMIC_UPDATE:
                return true;
        }
        return false;
    }

    // on Dynamic Registration Endpoint access for creating client
    @Override
    public void executeOnDynamicClientRegister(
            ClientRegistrationContext context,
            RegistrationAuth authType) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Dynamic Client Registration Endpoint - creating client");
        verifySecureSigningAlogirhtm(OIDCAdvancedConfigWrapper.fromClientRepresentation(context.getClient()).getIdTokenSignedResponseAlg());
        org.keycloak.jose.jws.Algorithm algorithm = OIDCAdvancedConfigWrapper.fromClientRepresentation(context.getClient()).getRequestObjectSignatureAlg();
        String alg = algorithm != null ? algorithm.name() : null;
        verifySecureSigningAlogirhtm(alg);
    }

    // on Dynamic Registration Endpoint access for updating client
    @Override
    public void executeOnDynamicClientUpdate(
            ClientRegistrationContext context,
            RegistrationAuth authType,
            ClientModel client) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Dynamic Client Registration Endpoint - updating client");
        verifySecureSigningAlogirhtm(OIDCAdvancedConfigWrapper.fromClientRepresentation(context.getClient()).getIdTokenSignedResponseAlg());
        org.keycloak.jose.jws.Algorithm algorithm = OIDCAdvancedConfigWrapper.fromClientRepresentation(context.getClient()).getRequestObjectSignatureAlg();
        String alg = algorithm != null ? algorithm.name() : null;
        verifySecureSigningAlogirhtm(alg);
    }

    private void verifySecureSigningAlogirhtm(String signatureAlgorithm) throws ClientPolicyException {
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
