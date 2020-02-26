package org.keycloak.services.clientpolicy.executor.impl;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;

public class SecureRequestObjectExecutor extends AbstractObsoleteClientPolicyExecutor {

    private static final Logger logger = Logger.getLogger(SecureRequestObjectExecutor.class);

    public SecureRequestObjectExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    public boolean isExecutedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.AUTHORIZATION_REQUEST:
                return true;
        }
        return false;
    }

    // on Authorization Endpoint access for authorization request
    @Override
    public void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Authz Endpoint - authz request");

        // Only support GET, not yet consider POST
        MultivaluedMap<String, String> params = session.getContext().getUri().getQueryParameters();

        // confirm whether request object exists
        if (params.getFirst(OIDCLoginProtocol.REQUEST_PARAM) == null && params.getFirst(OIDCLoginProtocol.REQUEST_URI_PARAM) == null) {
            ClientPolicyLogger.log(logger, "request object not exist.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter");
        }

        // https scheme for request_uri
        String requestUriParam = params.getFirst(OIDCLoginProtocol.REQUEST_URI_PARAM);
        if (requestUriParam != null && !requestUriParam.startsWith("https://")) {
            ClientPolicyLogger.log(logger, "request_uri scheme is not https.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter: request_uri");
        }

        // confirm whether all parameters in query string are included in the request object, and have the same values
        // argument "request" are parameters overriden by parameters in request object
        if (KNOWN_REQ_PARAMS.stream().filter(s->params.containsKey(s)).anyMatch(s->!isSameParameterIncluded(s, params.getFirst(s), request))) {
            ClientPolicyLogger.log(logger, "not all parameters in query string are included in the request object, and have the same values.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter");
        }

        // need "exp" claim
        if (request.getAdditionalReqParams().get("exp") == null) {
            ClientPolicyLogger.log(logger, "exp claim not incuded.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Missing parameter : exp");
        }

        // request object not expired
        long exp = Long.parseLong(request.getAdditionalReqParams().get("exp"));
        if (Time.currentTime() > exp) { // TODO: Time.currentTime() is int while exp is long...
            ClientPolicyLogger.log(logger, "request object expired.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Request Expired");
        }

        ClientPolicyLogger.log(logger, "Passed.");
    }

    private boolean isSameParameterIncluded(String param, String value, AuthorizationEndpointRequest request) {
        ClientPolicyLogger.log(logger, "param = " + param + ", value = " + value);
        if (OIDCLoginProtocol.CLIENT_ID_PARAM.equals(param)) {
            return request.getClientId().equals(value);
        } else if (OIDCLoginProtocol.RESPONSE_TYPE_PARAM.equals(param)) {
            return request.getResponseType().equals(value);
        } else if (OIDCLoginProtocol.RESPONSE_MODE_PARAM.equals(param)) {
            return request.getResponseMode().equals(value);
        } else if (OIDCLoginProtocol.REDIRECT_URI_PARAM.equals(param)) {
            return request.getRedirectUriParam().equals(value);
        } else if (OIDCLoginProtocol.STATE_PARAM.equals(param)) {
            return request.getState().equals(value);
        } else if (OIDCLoginProtocol.SCOPE_PARAM.equals(param)) {
            return request.getScope().equals(value);
        } else if (OIDCLoginProtocol.LOGIN_HINT_PARAM.equals(param)) {
            return request.getLoginHint().equals(value);
        } else if (OIDCLoginProtocol.PROMPT_PARAM.equals(param)) {
            return request.getPrompt().equals(value);
        } else if (OIDCLoginProtocol.NONCE_PARAM.equals(param)) {
            return request.getNonce().equals(value);
        } else if (OIDCLoginProtocol.MAX_AGE_PARAM.equals(param)) {
            return request.getMaxAge().toString().equals(value);
        } else if (OIDCLoginProtocol.UI_LOCALES_PARAM.equals(param)) {
            return request.getUiLocales().equals(value);
        } else if (OIDCLoginProtocol.CLAIMS_PARAM.equals(param)) {
            return request.getClaims().equals(value);
        } else if (OIDCLoginProtocol.ACR_PARAM.equals(param)) {
            return request.getAcr().equals(value);
        } else if (OIDCLoginProtocol.CODE_CHALLENGE_PARAM.equals(param)) {
            return request.getCodeChallenge().equals(value);
        } else if (OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM.equals(param)) {
            return request.getCodeChallengeMethod().equals(value);
        }
        return true;
    }

    private static final Set<String> KNOWN_REQ_PARAMS = new HashSet<>();
    static {
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.CLIENT_ID_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.RESPONSE_TYPE_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.RESPONSE_MODE_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.REDIRECT_URI_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.STATE_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.SCOPE_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.PROMPT_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.NONCE_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.MAX_AGE_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.UI_LOCALES_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.REQUEST_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.REQUEST_URI_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.CLAIMS_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.ACR_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.CODE_CHALLENGE_PARAM);
        KNOWN_REQ_PARAMS.add(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM);
        KNOWN_REQ_PARAMS.add(OAuth2Constants.DISPLAY);
        KNOWN_REQ_PARAMS.add(OAuth2Constants.UI_LOCALES_PARAM);
    }

}