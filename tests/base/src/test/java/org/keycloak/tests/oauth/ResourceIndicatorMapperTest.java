package org.keycloak.tests.oauth;

import java.io.IOException;
import java.util.List;

import org.keycloak.common.Profile;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.ResourceIndicatorMapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.RealmConfigBuilder;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.page.LogoutConfirmPage;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.IntrospectionResponse;
import org.keycloak.testsuite.util.oauth.TokenRevocationResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@KeycloakIntegrationTest(config = ResourceIndicatorMapperTest.ResourceIndicatorMapperServerConfig.class)
@TestMethodOrder(MethodOrderer.MethodName.class)
public class ResourceIndicatorMapperTest {

    @InjectRealm(config = ResourceIndicatorMapperRealmConfig.class)
    ManagedRealm testRealm;

    @InjectOAuthClient
    OAuthClient oAuthClient;

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @InjectPage
    protected LogoutConfirmPage logoutConfirmPage;

    private static final String TEST_REALM = "MyTestRealm";
    private static final String TEST_CLIENT = "MyTestClient";
    private static final String TEST_CLIENT_SECRET = "secret";
    private static final String TEST_USER = "MyTestUser";
    private static final String TEST_USER_PASSWORD = "password";
    private static final String TEST_MAPPER = "resource-indicator";

    private static final String POLICY_NAME = "MyPolicy";
    private static final String PROFILE_NAME = "MyProfile";

    @BeforeEach
    public void setup() {
        // It is enough to be executed only once before start testing.
        // However, static method annotated @BeforeAll cannot refer to the member runOnServer, so it is executed here.
        // It is better to do that in ResourceIndicatorMapperRealmConfig.configure, but no way to do that in that method.
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName(TEST_REALM);
            ClientModel target = realm.getClientByClientId(TEST_CLIENT);
            if (target.getProtocolMapperByName(OIDCLoginProtocol.LOGIN_PROTOCOL, TEST_MAPPER) == null) {
                target.addProtocolMapper(ResourceIndicatorMapper.create(TEST_MAPPER, true, true,
                        List.of("https://resource.example.com/v1", "https://example.com/resource")));
                target.setServiceAccountsEnabled(true);
            }

            // disable verify profile required action
            RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(UserModel.RequiredAction.VERIFY_PROFILE.name());
            if (model.isEnabled()) {
                model.setDefaultAction(false);
                model.setEnabled(false);
                realm.updateRequiredActionProvider(model);
            }
        });
    }

    @AfterEach
    public void cleanup() {
        // logout
        oAuthClient.openLogoutForm();
        logoutConfirmPage.assertCurrent();
        logoutConfirmPage.confirmLogout();
    }

    @Test
    public void testSuccessfulBindMapper() throws IOException {
        // authorization code grant
        // resource specified in an authorization request
        // resource specified in a token request
        // -> bind with resource specified in an authorization request
        String resourceInAuthorizationRequest = "https://resource.example.com/v1";
        String resourceInTokenRequest = resourceInAuthorizationRequest;
        String code = loginUserAndGetCode(TEST_CLIENT, resourceInAuthorizationRequest);
        AccessTokenResponse tokenResponse = oAuthClient.
                client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).resource(resourceInTokenRequest).send();
        assertTokenValidResponse(tokenResponse, resourceInAuthorizationRequest);

        // introspect
        //  -> bind with resource specified in an authorization request
        IntrospectionResponse introspectionResponse = oAuthClient.doIntrospectionAccessTokenRequest(tokenResponse.getAccessToken());
        assertIntrospectValidResponse(introspectionResponse, resourceInAuthorizationRequest);

        // refresh
        //  resource not specified in a token refresh request
        //  -> bind with resource specified in an authorization request
        tokenResponse = oAuthClient.doRefreshTokenRequest(tokenResponse.getRefreshToken());
        assertRefreshTokenResponse(tokenResponse, resourceInAuthorizationRequest);

        // revoke
        TokenRevocationResponse revokeResponse = oAuthClient.doTokenRevoke(tokenResponse.getAccessToken());
        assertRevokeValidResponse(revokeResponse, tokenResponse);

        // authorization code grant
        //  resource not specified in an authorization request
        //  resource not specified in a token request
        //  -> not bind
        resourceInAuthorizationRequest = null;
        resourceInTokenRequest = null;
        code = ssoLoginUserAndGetCode(TEST_CLIENT, resourceInAuthorizationRequest);
        tokenResponse = oAuthClient.
                client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).resource(resourceInTokenRequest).send();
        assertNotBindTokenValidResponse(tokenResponse);

        // authorization code grant
        //  resource specified in an authorization request
        //  resource specified in a token request
        //  -> not bind
        resourceInAuthorizationRequest = "https://resource.example.com/v1";
        resourceInTokenRequest = "https://different.resource.example.com/";
        code = ssoLoginUserAndGetCode(TEST_CLIENT, resourceInAuthorizationRequest);
        tokenResponse = oAuthClient.
                client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).resource(resourceInTokenRequest).send();
        assertNotBindTokenValidResponse(tokenResponse);

        // authorization code grant
        //  resource specified in an authorization request
        //  resource not specified in a token request
        //  -> bind with resource specified in an authorization request
        resourceInAuthorizationRequest = "https://resource.example.com/v1";
        resourceInTokenRequest = null;
        code = ssoLoginUserAndGetCode(TEST_CLIENT, resourceInAuthorizationRequest);
        tokenResponse = oAuthClient.
                client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).resource(resourceInTokenRequest).send();
        assertTokenValidResponse(tokenResponse, resourceInAuthorizationRequest);

        // refresh
        //  resource specified in a token refresh request, but it is different from the one in the authorization request
        //  -> not bind
        tokenResponse = oAuthClient.refreshRequest(tokenResponse.getRefreshToken()).resource("https://different.resource.example.com/").send();
        assertNotBindTokenValidResponse(tokenResponse);
    }

    @Test
    public void testNotBindMapper() {
        // setup realm
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName(TEST_REALM);
            ClientModel target = realm.getClientByClientId(TEST_CLIENT);
            ProtocolMapperModel model = target.getProtocolMapperByName(OIDCLoginProtocol.LOGIN_PROTOCOL, TEST_MAPPER);
            if (model != null) {
                target.removeProtocolMapper(model);
            }
        });

        // resource specified in an authorization request but no mapper applied - not bind
        String resource = "https://resource.example.com/v1";
        String code = loginUserAndGetCode(TEST_CLIENT, resource);
        AccessTokenResponse tokenResponse = oAuthClient.
                client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).resource(resource).send();
        assertNotBindTokenValidResponse(tokenResponse);
    }

    public static class ResourceIndicatorMapperRealmConfig implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            realm.name(TEST_REALM);
            realm.addClient(TEST_CLIENT).secret(TEST_CLIENT_SECRET).redirectUris("http://127.0.0.1:8500/callback/oauth");
            realm.addUser(TEST_USER).password(TEST_USER_PASSWORD);
            return realm;
        }
    }

    public static class ResourceIndicatorMapperServerConfig implements KeycloakServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.RESOURCE_INDICATOR);
        }
    }

    private String loginUserAndGetCode(String clientId, String resource) {
        oAuthClient.client(clientId);
        oAuthClient.loginForm().resource(resource).doLogin(TEST_USER, TEST_USER_PASSWORD);

        String code = oAuthClient.parseLoginResponse().getCode();
        Assertions.assertNotNull(code);
        return code;
    }

    private String ssoLoginUserAndGetCode(String clientId, String resource) {
        oAuthClient.client(clientId);
        oAuthClient.loginForm().resource(resource).open();

        String code = oAuthClient.parseLoginResponse().getCode();
        Assertions.assertNotNull(code);
        return code;
    }

    private void assertTokenValidResponse(AccessTokenResponse tokenResponse, String resource) {
        Assertions.assertEquals(200, tokenResponse.getStatusCode());
        AccessToken accessToken = oAuthClient.verifyToken(tokenResponse.getAccessToken());
        Assertions.assertEquals(1, accessToken.getAudience().length);
        Assertions.assertEquals(resource, accessToken.getAudience()[0]);
        IDToken idToken = oAuthClient.verifyIDToken(tokenResponse.getIdToken());
        Assertions.assertEquals(1, idToken.getAudience().length);
        Assertions.assertEquals(TEST_CLIENT, idToken.getAudience()[0]);
    }

    private void assertIntrospectValidResponse(IntrospectionResponse introspectionResponse, String resource) throws IOException {
        Assertions.assertEquals(200, introspectionResponse.getStatusCode());
        Assertions.assertEquals(1, introspectionResponse.asTokenMetadata().getAudience().length);
        Assertions.assertEquals(resource, introspectionResponse.asTokenMetadata().getAudience()[0]);
    }

    private void assertRefreshTokenResponse(AccessTokenResponse tokenResponse, String resource) {
        Assertions.assertEquals(200, tokenResponse.getStatusCode());
        AccessToken accessToken = oAuthClient.verifyToken(tokenResponse.getAccessToken());
        Assertions.assertEquals(1, accessToken.getAudience().length);
        Assertions.assertEquals(resource, accessToken.getAudience()[0]);
    }

    private void assertRevokeValidResponse(TokenRevocationResponse revokeResponse, AccessTokenResponse tokenResponse) throws IOException {
        Assertions.assertEquals(200, revokeResponse.getStatusCode());
        IntrospectionResponse introspectionResponse = oAuthClient.doIntrospectionAccessTokenRequest(tokenResponse.getAccessToken());
        Assertions.assertEquals(200, introspectionResponse.getStatusCode());
        Assertions.assertFalse(introspectionResponse.asTokenMetadata().isActive());
    }

    private void assertNotBindTokenValidResponse(AccessTokenResponse tokenResponse) {
        Assertions.assertEquals(200, tokenResponse.getStatusCode());
        AccessToken accessToken = oAuthClient.verifyToken(tokenResponse.getAccessToken());
        Assertions.assertNull(accessToken.getAudience());
    }
}
