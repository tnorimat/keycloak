package org.keycloak.testsuite.client;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;
import static org.keycloak.testsuite.admin.ApiUtil.findUserByUsername;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.jboss.logging.Logger;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistration;
import org.keycloak.client.registration.ClientRegistrationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.events.Details;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.ClientManager;
import org.keycloak.testsuite.util.ClientPolicyUtil;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.UserBuilder;

public class ClientPolicyTest extends AbstractKeycloakTest {

    private static final Logger logger = Logger.getLogger(ClientPolicyTest.class);

    static final String REALM_NAME = "test";
    static final String TEST_CLIENT = "test-app";

    ClientRegistration reg;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Before
    public void before() throws Exception {
        // get initial access token for Dynamic Client Registration with authentication
        reg = ClientRegistration.create().url(suiteContext.getAuthServerInfo().getContextRoot() + "/auth", REALM_NAME).build();
        ClientInitialAccessPresentation token = adminClient.realm(REALM_NAME).clientInitialAccess().create(new ClientInitialAccessCreatePresentation(0, 10));
        reg.auth(Auth.token(token));
        // use client_id = "test-app" for authz code grant
        ClientManager.realm(adminClient.realm(REALM_NAME)).clientId(TEST_CLIENT).directAccessGrant(true);
        oauth.clientId(TEST_CLIENT);
    }

    @After
    public void after() throws Exception {
        reg.close();
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);

        UserBuilder user = UserBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .username("no-permissions")
                .addRoles("user")
                .password("password");
        realm.getUsers().add(user.build());

        realm.getClients().stream().filter(clientRepresentation -> {

            return TEST_CLIENT.equals(clientRepresentation.getClientId());

        }).forEach(clientRepresentation -> {

            clientRepresentation.setFullScopeAllowed(false);

        });

        testRealms.add(realm);

    }

    @Test
    public void createAndUpdateClientByAdminRestApiUnderPolicy() {
        ClientPolicyUtil.addAdminRestApiPolicy(logger, REALM_NAME, adminClient, testContext);
        String clientDbId = ClientPolicyUtil.createOidcConfidentialClientByAdminRestApi("beer-app", REALM_NAME, adminClient);
        ClientPolicyUtil.updateClientByAdminRestApi("beer-app", REALM_NAME, adminClient, (ClientRepresentation clientRep) -> {
            List<String> redirectUris = clientRep.getRedirectUris();
            redirectUris.add("https://localhost:8543/auth/realms/master/app/auth");
            clientRep.setRedirectUris(redirectUris);
            return clientRep;});
        ClientPolicyUtil.removeClientByAdminRestApi(clientDbId, REALM_NAME, adminClient);
    }

    @Test
    public void createClientUnderPolicy() throws ClientRegistrationException {
        //ClientPolicyUtil.addAnonymousPolicy(logger, REALM_NAME, adminClient, testContext);
        ClientPolicyUtil.addAuthPolicy(logger, REALM_NAME, adminClient, testContext);
        //ClientPolicyUtil.addFAPIROPolicy(logger, REALM_NAME, adminClient, testContext);

        OIDCClientRepresentation client = createRep();
        client.setTokenEndpointAuthMethod(OIDCLoginProtocol.TLS_CLIENT_AUTH);
        List<String> redirectUris = new ArrayList<>();
        client.setRedirectUris(Collections.singletonList("https://localhost:8543"));
        client.setTlsClientCertificateBoundAccessTokens(Boolean.TRUE);
        OIDCClientRepresentation response = reg.oidc().create(client);

        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientIdIssuedAt());
        assertNotNull(response.getClientId());
        //assertNotNull(response.getClientSecret());
        //assertEquals(0, response.getClientSecretExpiresAt().intValue());
        assertNotNull(response.getRegistrationClientUri());
        assertEquals("RegistrationAccessTokenTest", response.getClientName());
        assertEquals("http://root", response.getClientUri());
        assertEquals(1, response.getRedirectUris().size());
        assertEquals("https://localhost:8543", response.getRedirectUris().get(0));
        assertEquals(Arrays.asList("code", "none"), response.getResponseTypes());
        assertEquals(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.REFRESH_TOKEN), response.getGrantTypes());
        assertEquals(OIDCLoginProtocol.TLS_CLIENT_AUTH, response.getTokenEndpointAuthMethod());
        Assert.assertNull(response.getUserinfoSignedResponseAlg());
    }

    @Test
    public void updateClientUnderPolicy() throws ClientRegistrationException {
        ClientPolicyUtil.addAuthPolicy(logger, REALM_NAME, adminClient, testContext);

        OIDCClientRepresentation client = createRep();
        client.setTokenEndpointAuthMethod(OIDCLoginProtocol.TLS_CLIENT_AUTH);
        List<String> redirectUris = new ArrayList<>();
        client.setRedirectUris(Collections.singletonList("https://redirect"));
        OIDCClientRepresentation response = reg.oidc().create(client);
        reg.auth(Auth.token(response));

        response.setRedirectUris(Collections.singletonList("http://newredirect"));
        response.setResponseTypes(Arrays.asList("code", "id_token token", "code id_token token"));
        response.setGrantTypes(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.REFRESH_TOKEN, OAuth2Constants.PASSWORD));

        OIDCClientRepresentation updated = reg.oidc().update(response);

        assertTrue(CollectionUtil.collectionEquals(Collections.singletonList("http://newredirect"), updated.getRedirectUris()));
        assertTrue(CollectionUtil.collectionEquals(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.IMPLICIT, OAuth2Constants.REFRESH_TOKEN, OAuth2Constants.PASSWORD), updated.getGrantTypes()));
        assertTrue(CollectionUtil.collectionEquals(Arrays.asList(OAuth2Constants.CODE, OIDCResponseType.NONE, OIDCResponseType.ID_TOKEN, "id_token token", "code id_token", "code token", "code id_token token"), updated.getResponseTypes()));
    }

    @Test
    public void testFAPIROPolicy() throws Exception {
        ClientPolicyUtil.addAuthPolicy(logger, REALM_NAME, adminClient, testContext);
        ClientPolicyUtil.addFAPIROPolicy(logger, REALM_NAME, adminClient, testContext, TEST_CLIENT);
        try {
            setPkceActivationSettings(TEST_CLIENT, OAuth2Constants.PKCE_METHOD_S256);

            ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), TEST_CLIENT);
            ClientRepresentation clientRep = clientResource.toRepresentation();
            List<String> redirectUris = clientRep.getRedirectUris();
            redirectUris.add("https://localhost:8543/auth/realms/master/app/auth");
            clientRep.setRedirectUris(redirectUris);
            clientResource.update(clientRep);

            String codeVerifier = "1a345A7890123456r8901c3456789012b45K7890l23"; // 43
            String codeChallenge = generateS256CodeChallenge(codeVerifier);
            oauth.codeChallenge(codeChallenge);
            oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
            oauth.nonce("bjapewiziIE083d");

            oauth.doLogin("test-user@localhost", "password");

            EventRepresentation loginEvent = events.expectLogin().assertEvent();

            String sessionId = loginEvent.getSessionId();
            String codeId = loginEvent.getDetails().get(Details.CODE_ID);

            String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

            oauth.codeVerifier(codeVerifier);

            expectSuccessfulResponseFromTokenEndpoint(codeId, sessionId, code);
        } finally {
            setPkceActivationSettings(TEST_CLIENT, null);
        }
    }

    @Test
    public void testFAPIRWPolicy() throws Exception {
        ClientPolicyUtil.addFAPIRWPolicy(logger, REALM_NAME, adminClient, testContext, TEST_CLIENT);
        try {
            setPkceActivationSettings(TEST_CLIENT, OAuth2Constants.PKCE_METHOD_S256);

            ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), TEST_CLIENT);
            ClientRepresentation clientRep = clientResource.toRepresentation();
            List<String> redirectUris = clientRep.getRedirectUris();
            redirectUris.add("https://localhost:8543/auth/realms/master/app/auth");
            clientRep.setRedirectUris(redirectUris);
            clientResource.update(clientRep);

            String codeVerifier = "1a345A7890123456r8901c3456789012b45K7890l23"; // 43
            String codeChallenge = generateS256CodeChallenge(codeVerifier);
            oauth.codeChallenge(codeChallenge);
            oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
            oauth.nonce("bjapewiziIE083d");

            oauth.doLogin("test-user@localhost", "password");

            EventRepresentation loginEvent = events.expectLogin().assertEvent();

            String sessionId = loginEvent.getSessionId();
            String codeId = loginEvent.getDetails().get(Details.CODE_ID);

            String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

            oauth.codeVerifier(codeVerifier);

            expectSuccessfulResponseFromTokenEndpoint(codeId, sessionId, code);
        } finally {
            setPkceActivationSettings(TEST_CLIENT, null);
        }
    }

    /*
    @Test
    public void testPolicyToTestClientIpAddress() throws Exception {
        List<String> ipAddrs = new ArrayList<>();
        ipAddrs.add("0.0.0.0");
        ipAddrs.add("127.0.0.1");
        ClientPolicyUtil.addPolicyToTestClientIpAddress(logger, REALM_NAME, adminClient, testContext, ipAddrs);
        try {
            ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), TEST_CLIENT);
            ClientRepresentation clientRep = clientResource.toRepresentation();

            oauth.doLogin("test-user@localhost", "password");

            EventRepresentation loginEvent = events.expectLogin().assertEvent();

            String sessionId = loginEvent.getSessionId();
            String codeId = loginEvent.getDetails().get(Details.CODE_ID);

            String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

            expectSuccessfulResponseFromTokenEndpoint(codeId, sessionId, code);

        } finally {
        }
    }
    */

    private void setPkceActivationSettings(String clientId, String codeChallengeMethodName) {
        ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), clientId);
        ClientRepresentation clientRep = clientResource.toRepresentation();
        OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep).setPkceCodeChallengeMethod(codeChallengeMethodName);
        clientResource.update(clientRep);
    }

    private String generateS256CodeChallenge(String codeVerifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(codeVerifier.getBytes("ISO_8859_1"));
        byte[] digestBytes = md.digest();
        String codeChallenge = Base64Url.encode(digestBytes);
        return codeChallenge;
    }

    private OIDCClientRepresentation createRep() {
        OIDCClientRepresentation client = new OIDCClientRepresentation();
        client.setClientName("RegistrationAccessTokenTest");
        client.setClientUri("http://root");
        client.setRedirectUris(Collections.singletonList("http://redirect"));
        return client;
    }

    private void expectSuccessfulResponseFromTokenEndpoint(String codeId, String sessionId, String code)  throws Exception {
        OAuthClient.AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        assertEquals(200, response.getStatusCode());
        Assert.assertThat(response.getExpiresIn(), allOf(greaterThanOrEqualTo(250), lessThanOrEqualTo(300)));
        Assert.assertThat(response.getRefreshExpiresIn(), allOf(greaterThanOrEqualTo(1750), lessThanOrEqualTo(1800)));
        assertEquals("bearer", response.getTokenType());

        String expectedKid = oauth.doCertsRequest(REALM_NAME).getKeys()[0].getKeyId();

        JWSHeader header = new JWSInput(response.getAccessToken()).getHeader();
        assertEquals("RS256", header.getAlgorithm().name());
        assertEquals("JWT", header.getType());
        assertEquals(expectedKid, header.getKeyId());
        assertNull(header.getContentType());

        header = new JWSInput(response.getIdToken()).getHeader();
        assertEquals("RS256", header.getAlgorithm().name());
        assertEquals("JWT", header.getType());
        assertEquals(expectedKid, header.getKeyId());
        assertNull(header.getContentType());

        header = new JWSInput(response.getRefreshToken()).getHeader();
        assertEquals("HS256", header.getAlgorithm().name());
        assertEquals("JWT", header.getType());
        assertNull(header.getContentType());

        AccessToken token = oauth.verifyToken(response.getAccessToken());

        assertEquals(findUserByUsername(adminClient.realm(REALM_NAME), "test-user@localhost").getId(), token.getSubject());
        Assert.assertNotEquals("test-user@localhost", token.getSubject());
        assertEquals(sessionId, token.getSessionState());
        assertEquals(1, token.getRealmAccess().getRoles().size());
        assertTrue(token.getRealmAccess().isUserInRole("user"));
        assertEquals(1, token.getResourceAccess(oauth.getClientId()).getRoles().size());
        assertTrue(token.getResourceAccess(oauth.getClientId()).isUserInRole("customer-user"));

        EventRepresentation event = events.expectCodeToToken(codeId, sessionId).assertEvent();
        
        assertEquals(token.getId(), event.getDetails().get(Details.TOKEN_ID));
        assertEquals(oauth.parseRefreshToken(response.getRefreshToken()).getId(), event.getDetails().get(Details.REFRESH_TOKEN_ID));
        assertEquals(sessionId, token.getSessionState());
        
        // make sure PKCE does not affect token refresh on Token Endpoint
        
        String refreshTokenString = response.getRefreshToken();
        RefreshToken refreshToken = oauth.parseRefreshToken(refreshTokenString);

        Assert.assertNotNull(refreshTokenString);
        Assert.assertThat(token.getExpiration() - getCurrentTime(), allOf(greaterThanOrEqualTo(200), lessThanOrEqualTo(350)));
        int actual = refreshToken.getExpiration() - getCurrentTime();
        Assert.assertThat(actual, allOf(greaterThanOrEqualTo(1799), lessThanOrEqualTo(1800)));
        assertEquals(sessionId, refreshToken.getSessionState());

        setTimeOffset(2);

        OAuthClient.AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(refreshTokenString, "password");
        
        AccessToken refreshedToken = oauth.verifyToken(refreshResponse.getAccessToken());
        RefreshToken refreshedRefreshToken = oauth.parseRefreshToken(refreshResponse.getRefreshToken());

        assertEquals(200, refreshResponse.getStatusCode());
        assertEquals(sessionId, refreshedToken.getSessionState());
        assertEquals(sessionId, refreshedRefreshToken.getSessionState());

        Assert.assertThat(refreshResponse.getExpiresIn(), allOf(greaterThanOrEqualTo(250), lessThanOrEqualTo(300)));
        Assert.assertThat(refreshedToken.getExpiration() - getCurrentTime(), allOf(greaterThanOrEqualTo(250), lessThanOrEqualTo(300)));

        Assert.assertThat(refreshedToken.getExpiration() - token.getExpiration(), allOf(greaterThanOrEqualTo(1), lessThanOrEqualTo(10)));
        Assert.assertThat(refreshedRefreshToken.getExpiration() - refreshToken.getExpiration(), allOf(greaterThanOrEqualTo(1), lessThanOrEqualTo(10)));

        Assert.assertNotEquals(token.getId(), refreshedToken.getId());
        Assert.assertNotEquals(refreshToken.getId(), refreshedRefreshToken.getId());

        assertEquals("bearer", refreshResponse.getTokenType());

        assertEquals(findUserByUsername(adminClient.realm(REALM_NAME), "test-user@localhost").getId(), refreshedToken.getSubject());
        Assert.assertNotEquals("test-user@localhost", refreshedToken.getSubject());

        assertEquals(1, refreshedToken.getRealmAccess().getRoles().size());
        Assert.assertTrue(refreshedToken.getRealmAccess().isUserInRole("user"));

        assertEquals(1, refreshedToken.getResourceAccess(oauth.getClientId()).getRoles().size());
        Assert.assertTrue(refreshedToken.getResourceAccess(oauth.getClientId()).isUserInRole("customer-user"));

        EventRepresentation refreshEvent = events.expectRefresh(event.getDetails().get(Details.REFRESH_TOKEN_ID), sessionId).assertEvent();
        Assert.assertNotEquals(event.getDetails().get(Details.TOKEN_ID), refreshEvent.getDetails().get(Details.TOKEN_ID));
        Assert.assertNotEquals(event.getDetails().get(Details.REFRESH_TOKEN_ID), refreshEvent.getDetails().get(Details.UPDATED_REFRESH_TOKEN_ID));

        setTimeOffset(0);
    }
}
