package org.keycloak.protocol.ciba;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.OAuth2Constants;
import org.keycloak.protocol.ciba.decoupledauthn.DelegateDecoupledAuthenticationProvider;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;

public class CIBAAuthDelegationRequest extends JsonWebToken {

    @JsonProperty(DelegateDecoupledAuthenticationProvider.DECOUPLED_AUTHN_ID)
    protected String decoupledAuthId;

    @JsonProperty(OAuth2Constants.SCOPE)
    protected String scope;

    @JsonProperty(DelegateDecoupledAuthenticationProvider.DECOUPLED_AUTHN_IS_CONSENT_REQUIRED)
    protected boolean isConsentRequired;

    @JsonProperty(DelegateDecoupledAuthenticationProvider.DECOUPLED_DEFAULT_CLIENT_SCOPE)
    protected String defaultClientScope;

    @JsonProperty(CIBAConstants.BINDING_MESSAGE)
    protected String bindingMessage;

    @JsonProperty(CIBAConstants.USER_CODE)
    protected String userCode;

    public String getDecoupledAuthId() {
        return decoupledAuthId;
    }

    public void setDecoupledAuthId(String decoupledAuthId) {
        this.decoupledAuthId = decoupledAuthId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public boolean getIsConsentRequired() {
        return isConsentRequired;
    }

    public void setIsConsentRequired(boolean isConsentRequired) {
        this.isConsentRequired = isConsentRequired;
    }

    public String getDefaultClientScope() {
        return defaultClientScope;
    }

    public void setDefaultClientScope(String defaultClientScope) {
        this.defaultClientScope = defaultClientScope;
    }

    public String getBindingMessage() {
        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {
        this.bindingMessage = bindingMessage;
    }

    public String getUserCode() {
        return userCode;
    }

    public void setUserCode(String userCode) {
        this.userCode = userCode;
    }

}
