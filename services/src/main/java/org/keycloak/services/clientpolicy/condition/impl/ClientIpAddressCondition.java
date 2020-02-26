package org.keycloak.services.clientpolicy.condition.impl;

import javax.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;

public class ClientIpAddressCondition implements ClientPolicyCondition {

    private static final Logger logger = Logger.getLogger(ClientIpAddressCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientIpAddressCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public boolean isEvaluatedOnEvent(String event) {
        switch (event) {
            case ClientPolicyEvent.TOKEN_REQUEST:
            case ClientPolicyEvent.TOKEN_REFRESH:
            case ClientPolicyEvent.TOKEN_REVOKE:
            case ClientPolicyEvent.TOKEN_INTROSPECT:
            case ClientPolicyEvent.USERINFO_REQUEST:
            case ClientPolicyEvent.LOGOUT_REQUEST:
                return true;
        }
        return false;
    }

    // on Token Endpoint access for token request
    @Override
    public boolean isSatisfiedOnTokenRequest(
            MultivaluedMap<String, String> params,
            OAuth2CodeParser.ParseResult parseResult) {
        ClientPolicyLogger.log(logger, "Token Endpoint access for token request");
        return isIpAddressMathced();
    }

    // on Token Endpoint access for token refresh
    @Override
    public boolean isSatisfiedOnTokenRefresh(
            MultivaluedMap<String, String> params) {
        ClientPolicyLogger.log(logger, "Token Endpoint access for token refresh");
        return isIpAddressMathced();
    }

    // on Token Revocation Endpoint access for token revoke
    @Override
    public boolean isSatisfiedOnTokenRevoke(
            MultivaluedMap<String, String> params) {
        ClientPolicyLogger.log(logger, "Token Revocation Endpoint access for token revoke");
        return isIpAddressMathced();
    }

    // on Token Introspenction Endpoint access for token introspect
    @Override
    public boolean isSatisfiedOnTokenIntrospect(
            MultivaluedMap<String, String> params) {
        ClientPolicyLogger.log(logger, "Token Introspenction Endpoint access for token introspect");
        return isIpAddressMathced();
    }

    // on UserInfo Endpoint access for userinfo request
    @Override
    public boolean isSatisfiedOnUserInfoRequest(
            MultivaluedMap<String, String> params) {
        ClientPolicyLogger.log(logger, "UserInfo Endpoint access for userinfo request");
        return isIpAddressMathced();
    }

    // on Logout Endpoint access for logout request
    @Override
    public boolean isSatisfiedOnLogoutRequest(
            MultivaluedMap<String, String> params) {
        ClientPolicyLogger.log(logger, "Logout Endpoint access for logout request");
        return isIpAddressMathced();
    }

    private boolean isIpAddressMathced() {
        String ipAddr = session.getContext().getConnection().getRemoteAddr();

        componentModel.getConfig().get(ClientIpAddressConditionFactory.IPADDR).stream().forEach(i -> ClientPolicyLogger.log(logger, "ip address expected = " + i));
        ClientPolicyLogger.log(logger, "ip address expected = " + ipAddr);

        boolean isMatched = componentModel.getConfig().get(ClientIpAddressConditionFactory.IPADDR).stream().anyMatch(i -> i.equals(ipAddr));
        if (isMatched) {
           ClientPolicyLogger.log(logger, "ip address matched.");
        }  else {
           ClientPolicyLogger.log(logger, "ip address unmatched.");
        }
        return isMatched;
    }
}
