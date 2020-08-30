package org.keycloak.services.clientpolicy.executor;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.AuthorizationRequestContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

public class SecureRequestObjectExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(SecureRequestObjectExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    private AuthorizationEndpointRequestObject parsedRequestObject;

    public static final String INVALID_REQUEST_OBJECT = "invalid_request_object";

    public SecureRequestObjectExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case AUTHORIZATION_REQUEST:
                AuthorizationRequestContext authorizationRequestContext = (AuthorizationRequestContext)context;
                executeOnAuthorizationRequest(authorizationRequestContext.getparsedResponseType(),
                    authorizationRequestContext.getAuthorizationEndpointRequest(),
                    authorizationRequestContext.getRedirectUri());
                break;
            default:
                return;
        }
    }

    public void executeOnAuthorizationRequest(
            OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri) throws ClientPolicyException {
        ClientPolicyLogger.log(logger, "Authz Endpoint - authz request");

        // Only support GET, not yet consider POST
        MultivaluedMap<String, String> params = session.getContext().getUri().getQueryParameters();
        String requestParam = params.getFirst(OIDCLoginProtocol.REQUEST_PARAM);
        String requestUriParam = params.getFirst(OIDCLoginProtocol.REQUEST_URI_PARAM);

        // check whether whether request object exists
        if (requestParam == null && requestUriParam == null) {
            ClientPolicyLogger.log(logger, "request object not exist.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter");
        }

        // check whether request_uri is https scheme
        if (requestUriParam != null && !requestUriParam.startsWith("https://")) {
            ClientPolicyLogger.log(logger, "request_uri scheme is not https.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter: request_uri");
        }

        // check whether request object can be retrieved from request_uri
        String retrievedRequestObject = null;
        if (requestParam != null) {
            retrievedRequestObject = requestParam;
        } else {
            try (InputStream is = session.getProvider(HttpClientProvider.class).get(requestUriParam)) {
                retrievedRequestObject = StreamUtil.readString(is);
            } catch (IOException e) {
                ClientPolicyLogger.log(logger, "failed to retrieve request object from request_uri.");
                throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter: request_uri");
            }
        }

        // check whether request object can be parsed successfully
        JWSInput input;
        try {
            input = new JWSInput(retrievedRequestObject);
            parsedRequestObject = JsonSerialization.readValue(input.getContent(), AuthorizationEndpointRequestObject.class);
        } catch (JWSInputException | IOException e) {
            ClientPolicyLogger.log(logger, "failed to parse request object.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid request object");
        }

        DumpQueryParameters();
        DumpRequestObject();

        // check whether scope exists in both query parameter and request object
        if (params.getFirst(OIDCLoginProtocol.SCOPE_PARAM) == null || parsedRequestObject.getScope() == null) {
            ClientPolicyLogger.log(logger, "scope does not exists.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Missing parameter : scope");
        }

        // check whether "exp" claim exists
        if (parsedRequestObject.getExp() == null) {
            ClientPolicyLogger.log(logger, "exp claim not incuded.");
            throw new ClientPolicyException(INVALID_REQUEST_OBJECT, "Missing parameter : exp");
        }

        // check whether request object not expired
        long exp = parsedRequestObject.getExp().longValue();
        if (Time.currentTime() > exp) { // TODO: Time.currentTime() is int while exp is long...
            ClientPolicyLogger.log(logger, "request object expired.");
            throw new ClientPolicyException(INVALID_REQUEST_OBJECT, "Request Expired");
        }

        // check whether "aud" claim exists
        String[] aud = parsedRequestObject.getAudience();
        if (aud == null) {
            ClientPolicyLogger.log(logger, "aud claim not incuded.");
            throw new ClientPolicyException(INVALID_REQUEST_OBJECT, "Missing parameter : aud");
        }

        // check whether "aud" claim points to this keycloak as authz server
        String iss = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), session.getContext().getRealm().getName());
        if (!Arrays.asList(aud).contains(iss)) {
            ClientPolicyLogger.log(logger, "aud not points to the intented realm.");
            throw new ClientPolicyException(INVALID_REQUEST_OBJECT, "Invalid parameter : aud");
        }

        // confirm whether all parameters in query string are included in the request object, and have the same values
        // argument "request" are parameters overridden by parameters in request object
        if (KNOWN_REQ_PARAMS.stream().filter(s->params.containsKey(s)).anyMatch(s->!isSameParameterIncluded(s, params.getFirst(s), parsedRequestObject))) {
            ClientPolicyLogger.log(logger, "not all parameters in query string are included in the request object, and have the same values.");
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid parameter");
        }

        ClientPolicyLogger.log(logger, "Passed.");
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
    }

    private boolean isSameParameterIncluded(String param, String value, AuthorizationEndpointRequestObject request) {
        if (OIDCLoginProtocol.CLIENT_ID_PARAM.equals(param)) {
            return request.getClientId() != null && request.getClientId().equals(value);
        } else if (OIDCLoginProtocol.RESPONSE_TYPE_PARAM.equals(param)) {
            return request.getResponseType() != null && request.getResponseType().equals(value);
        } else if (OIDCLoginProtocol.RESPONSE_MODE_PARAM.equals(param)) {
            return request.getResponseMode() != null && request.getResponseMode().equals(value);
        } else if (OIDCLoginProtocol.REDIRECT_URI_PARAM.equals(param)) {
            return request.getRedirectUriParam() != null && request.getRedirectUriParam().equals(value);
        } else if (OIDCLoginProtocol.STATE_PARAM.equals(param)) {
            return request.getState() != null && request.getState().equals(value);
        } else if (OIDCLoginProtocol.SCOPE_PARAM.equals(param)) {
            return request.getScope() != null && request.getScope().equals(value);
        } else if (OIDCLoginProtocol.LOGIN_HINT_PARAM.equals(param)) {
            return request.getLoginHint() != null && request.getLoginHint().equals(value);
        } else if (OIDCLoginProtocol.PROMPT_PARAM.equals(param)) {
            return request.getPrompt() != null && request.getPrompt().equals(value);
        } else if (OIDCLoginProtocol.NONCE_PARAM.equals(param)) {
            return request.getNonce() != null && request.getNonce().equals(value);
        } else if (OIDCLoginProtocol.MAX_AGE_PARAM.equals(param)) {
            return request.getMax_age() != null && request.getMax_age().toString().equals(value);
        } else if (OIDCLoginProtocol.UI_LOCALES_PARAM.equals(param)) {
            return request.getUiLocales() != null && request.getUiLocales().equals(value);
        } else if (OIDCLoginProtocol.CLAIMS_PARAM.equals(param)) { // TODO : need some canonicalization for comparing in its meaning, not simply compare in its representation
            return request.getClaims() != null && request.getClaims().toString().equals(value);
        } else if (OIDCLoginProtocol.ACR_PARAM.equals(param)) {
            return request.getAcr() != null && request.getAcr().equals(value);
        } else if (OIDCLoginProtocol.CODE_CHALLENGE_PARAM.equals(param)) {
            return request.getCodeChallenge() != null && request.getCodeChallenge().equals(value);
        } else if (OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM.equals(param)) {
            return request.getCodeChallengeMethod() != null && request.getCodeChallengeMethod().equals(value);
        }
        return true;
    }

	public static class AuthorizationEndpointRequestObject extends JsonWebToken {

        @JsonProperty(OIDCLoginProtocol.CLIENT_ID_PARAM)
        String clientId;

        @JsonProperty(OIDCLoginProtocol.RESPONSE_TYPE_PARAM)
        String responseType;

        @JsonProperty(OIDCLoginProtocol.RESPONSE_MODE_PARAM)
        String responseMode;

        @JsonProperty(OIDCLoginProtocol.REDIRECT_URI_PARAM)
        String redirectUriParam;

        @JsonProperty(OIDCLoginProtocol.STATE_PARAM)
        String state;

        @JsonProperty(OIDCLoginProtocol.SCOPE_PARAM)
        String scope;

        @JsonProperty(OIDCLoginProtocol.LOGIN_HINT_PARAM)
        String loginHint;

        @JsonProperty(OIDCLoginProtocol.PROMPT_PARAM)
        String prompt;

        @JsonProperty(OIDCLoginProtocol.NONCE_PARAM)
        String nonce;

        Integer max_age;

        @JsonProperty(OIDCLoginProtocol.UI_LOCALES_PARAM)
        String uiLocales;

        @JsonProperty(OIDCLoginProtocol.CLAIMS_PARAM)
        JsonNode claims;

        @JsonProperty(OIDCLoginProtocol.ACR_PARAM)
        String acr;

        @JsonProperty(OAuth2Constants.DISPLAY)
        String display;

        @JsonProperty(OIDCLoginProtocol.CODE_CHALLENGE_PARAM)
        String codeChallenge;

        @JsonProperty(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM)
        String codeChallengeMethod;

        @JsonProperty(AdapterConstants.KC_IDP_HINT)
        String idpHint;

        @JsonProperty(Constants.KC_ACTION)
        String action;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId =  clientId;
        }

        public String getResponseType() {
            return responseType;
        }

        public void setResponseType(String responseType) {
            this.responseType = responseType;
        }

        public String getResponseMode() {
            return responseMode;
        }

        public void setResponseMode(String responseMode) {
            this.responseMode = responseMode;
        }

        public String getRedirectUriParam() {
            return redirectUriParam;
        }

        public void setRedirectUriParam(String redirectUriParam) {
            this.redirectUriParam = redirectUriParam;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getLoginHint() {
            return loginHint;
        }

        public void setLoginHint(String loginHint) {
            this.loginHint = loginHint;
        }

        public String getPrompt() {
            return prompt;
        }

        public void setPrompt(String prompt) {
            this.prompt = prompt;
        }

        public String getNonce() {
            return nonce;
        }

        public void getNonce(String nonce) {
            this.nonce = nonce;
        }

        public Integer getMax_age() {
            return max_age;
        }

        public void setMax_age(Integer max_age) {
            this.max_age = max_age;
        }

        public String getUiLocales() {
            return uiLocales;
        }

        public void setUiLocales(String uiLocales) {
            this.uiLocales = uiLocales;
        }

        public JsonNode getClaims() {
            return claims;
        }

        public void setClaims(JsonNode claims) {
            this.claims = claims;
        }

        public String getAcr() {
            return acr;
        }

        public void setAcr(String acr) {
            this.acr = acr;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }

        public void setCodeChallenge(String codeChallenge) {
            this.codeChallenge = codeChallenge;
        }

        public String getCodeChallengeMethod() {
            return codeChallengeMethod;
        }

        public void setCodeChallengeMethod(String codeChallengeMethod) {
            this.codeChallengeMethod = codeChallengeMethod;
        }

        public String getDisplay() {
            return display;
        }

        public void setDisplay(String display) {
            this.display = display;
        }

        public String getIdpHint() {
            return idpHint;
        }

        public void setIdpHint(String idpHint) {
            this.idpHint = idpHint;
        }

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            this.action = action;
        }

    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    private void DumpQueryParameters() {
        MultivaluedMap<String, String> params = session.getContext().getUri().getQueryParameters();
        params.keySet().forEach(s->ClientPolicyLogger.logv(logger, "Query Parameter : {0} = {1}", s, params.getFirst(s)));
    }

    private void DumpRequestObject() {
        if (parsedRequestObject.getId() != null) 
            ClientPolicyLogger.logv(logger, "Request Object : jti = {0}", parsedRequestObject.getId());
        if (parsedRequestObject.getType() != null)
            ClientPolicyLogger.logv(logger, "Request Object : typ = {0}", parsedRequestObject.getType());
        if (parsedRequestObject.getIssuer() != null)
            ClientPolicyLogger.logv(logger, "Request Object : iss = {0}", parsedRequestObject.getIssuer());
        if (parsedRequestObject.getSubject() != null)
            ClientPolicyLogger.logv(logger, "Request Object : sub = {0}", parsedRequestObject.getSubject());
        if (parsedRequestObject.getAudience() != null)
            Arrays.asList(parsedRequestObject.getAudience()).forEach(s->
            ClientPolicyLogger.logv(logger, "Request Object : aud = {0}", s));
        if (parsedRequestObject.getIssuedFor() != null)
            ClientPolicyLogger.logv(logger, "Request Object : azp = {0}", parsedRequestObject.getIssuedFor());
        if (parsedRequestObject.getExp() != null)
            ClientPolicyLogger.logv(logger, "Request Object : exp = {0}", parsedRequestObject.getExp());
        if (parsedRequestObject.getIat() != null)
            ClientPolicyLogger.logv(logger, "Request Object : iat = {0}", parsedRequestObject.getIat());
        if (parsedRequestObject.getNbf() != null)
            ClientPolicyLogger.logv(logger, "Request Object : nbf = {0}", parsedRequestObject.getNbf());

        if (parsedRequestObject.getClientId() != null)
            ClientPolicyLogger.logv(logger, "Request Object : client_id = {0}", parsedRequestObject.getClientId());
        if (parsedRequestObject.getResponseType() != null)
            ClientPolicyLogger.logv(logger, "Request Object : response_type = {0}", parsedRequestObject.getResponseType());
        if (parsedRequestObject.getResponseMode() != null)
            ClientPolicyLogger.logv(logger, "Request Object : response_mode = {0}", parsedRequestObject.getResponseMode());
        if (parsedRequestObject.getRedirectUriParam() != null)
            ClientPolicyLogger.logv(logger, "Request Object : redirect_uri = {0}", parsedRequestObject.getRedirectUriParam());
        if (parsedRequestObject.getState() != null)
            ClientPolicyLogger.logv(logger, "Request Object : state = {0}", parsedRequestObject.getState());
        if (parsedRequestObject.getScope() != null)
            ClientPolicyLogger.logv(logger, "Request Object : scope = {0}", parsedRequestObject.getScope());
        if (parsedRequestObject.getLoginHint() != null)
            ClientPolicyLogger.logv(logger, "Request Object : login_hint = {0}", parsedRequestObject.getLoginHint());
        if (parsedRequestObject.getPrompt() != null)
            ClientPolicyLogger.logv(logger, "Request Object : prompt = {0}", parsedRequestObject.getPrompt());
        if (parsedRequestObject.getNonce() != null)
            ClientPolicyLogger.logv(logger, "Request Object : nonce = {0}", parsedRequestObject.getNonce());
        if (parsedRequestObject.getMax_age() != null)
            ClientPolicyLogger.logv(logger, "Request Object : max_age = {0}", parsedRequestObject.getMax_age());
        if (parsedRequestObject.getUiLocales() != null)
            ClientPolicyLogger.logv(logger, "Request Object : ui_locales = {0}", parsedRequestObject.getUiLocales());
        if (parsedRequestObject.getClaims() != null) 
            ClientPolicyLogger.logv(logger, "Request Object : claims = {0}", parsedRequestObject.getClaims().toString());
        if (parsedRequestObject.getAcr() != null)
            ClientPolicyLogger.logv(logger, "Request Object : acr = {0}", parsedRequestObject.getAcr());
        if (parsedRequestObject.getCodeChallenge() != null)
            ClientPolicyLogger.logv(logger, "Request Object : code_challenge = {0}", parsedRequestObject.getCodeChallenge());
        if (parsedRequestObject.getCodeChallengeMethod() != null)
            ClientPolicyLogger.logv(logger, "Request Object : code_challenge_method = {0}", parsedRequestObject.getCodeChallengeMethod());
        if (parsedRequestObject.getDisplay() != null)
            ClientPolicyLogger.logv(logger, "Request Object : display = {0}", parsedRequestObject.getDisplay());

        if (parsedRequestObject.getOtherClaims() != null) parsedRequestObject.getOtherClaims().keySet().forEach(s->
            ClientPolicyLogger.logv(logger, "Request Object : {0} = {1}", s, parsedRequestObject.getOtherClaims().get(s).toString()));
    }
}