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

package org.keycloak.testsuite.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.hamcrest.Matchers;
import org.jboss.logging.Logger;
import org.junit.*;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistration;
import org.keycloak.client.registration.ClientRegistrationException;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.*;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.HardcodedRole;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.*;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.representations.oidc.TokenMetadataRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyProvider;
import org.keycloak.services.clientpolicy.DefaultClientPolicyProviderFactory;
import org.keycloak.services.clientpolicy.condition.*;
import org.keycloak.services.clientpolicy.executor.*;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.client.resources.TestApplicationResourceUrls;
import org.keycloak.testsuite.client.resources.TestOIDCEndpointsApplicationResource;
import org.keycloak.testsuite.rest.resource.TestingOIDCEndpointsApplicationResource;
import org.keycloak.testsuite.services.clientpolicy.condition.TestRaiseExeptionConditionFactory;
import org.keycloak.testsuite.util.MutualTLSUtils;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.function.Consumer;

import static org.junit.Assert.*;
import static org.keycloak.testsuite.AbstractTestRealmKeycloakTest.TEST_REALM_NAME;
import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;
import static org.keycloak.testsuite.admin.ApiUtil.findUserByUsername;

@EnableFeature(value = Profile.Feature.CLIENT_POLICIES, skipRestart = true)
public class ClientPolicyBasicsTest extends AbstractKeycloakTest {

    private static final Logger logger = Logger.getLogger(ClientPolicyBasicsTest.class);

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

        //System.setProperty("keycloak.profile", "preview");
        //Profile.init();

    }

    @After
    public void after() throws Exception {
        reg.close();

        //System.getProperties().remove("keycloak.profile");
        //Profile.init();
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);

        List<UserRepresentation> users = realm.getUsers();

        LinkedList<CredentialRepresentation> credentials = new LinkedList<>();
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue("password");
        credentials.add(password);

        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername("manage-clients");
        user.setCredentials(credentials);
        user.setClientRoles(Collections.singletonMap(Constants.REALM_MANAGEMENT_CLIENT_ID, Collections.singletonList(AdminRoles.MANAGE_CLIENTS)));

        users.add(user);

        user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername("create-clients");
        user.setCredentials(credentials);
        user.setClientRoles(Collections.singletonMap(Constants.REALM_MANAGEMENT_CLIENT_ID, Collections.singletonList(AdminRoles.CREATE_CLIENT)));
        user.setGroups(Arrays.asList("topGroup")); // defined in testrealm.json

        users.add(user);

        realm.setUsers(users);

        testRealms.add(realm);
    }

    //@Test
    public void testPurgePreviewProfile() throws ClientRegistrationException, ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createExecutor("PKCEEnforceExecutor", PKCEEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAugmentActivate(provider);
        });
        registerExecutor("PKCEEnforceExecutor", policyName);
        logger.info("... Registered Executor : PKCEEnforceExecutor");

        String clientId = "Zahlungs-App";
        String clientSecret = "secret";
        String cid = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setDefaultRoles((String[]) Arrays.asList("sample-client-role").toArray(new String[1]));
            clientRep.setSecret(clientSecret);
        });

        try {
            successfulLoginAndLogout(clientId, clientSecret);
 
            createCondition("ClientRolesCondition", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
                setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role")));
            });
            registerCondition("ClientRolesCondition", policyName);
            logger.info("... Registered Condition : ClientRolesCondition");

            failLoginByNotFollowingPKCE(clientId);

            System.getProperties().remove("keycloak.profile");
            Profile.init();

            successfulLoginAndLogout(clientId, clientSecret);

        } finally {
            System.setProperty("keycloak.profile", "preview");
            Profile.init();
            deleteClientByAdmin(cid);
        }
    }

    @Test
    public void testAdminClientRegisterUnacceptableAuthType() {
        setupPolicyAcceptableAuthType("MyPolicy");

        try {
            createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {
                clientRep.setClientAuthenticatorType(ClientIdAndSecretAuthenticator.PROVIDER_ID);
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(Errors.INVALID_REGISTRATION, e.getMessage());
        }
    }

    @Test
    public void testAdminClientRegisterAcceptableAuthType() throws ClientPolicyException {
        setupPolicyAcceptableAuthType("MyPolicy");

        String clientId = createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
        });
        try {
            assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());
        } finally {
            deleteClientByAdmin(clientId);
        }
    }

    @Test
    public void testAdminClientUpdateUnacceptableAuthType() throws ClientPolicyException {
        setupPolicyAcceptableAuthType("MyPolicy");

        String clientId = createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
        });

        try {
            assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());
 
            try {
                updateClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
                    clientRep.setClientAuthenticatorType(ClientIdAndSecretAuthenticator.PROVIDER_ID);
                });
                fail();
            } catch (BadRequestException bre) {}
            assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());

        } finally {
            deleteClientByAdmin(clientId);
        }
    }

    @Test
    public void testAdminClientUpdateAcceptableAuthType() throws ClientPolicyException {
        setupPolicyAcceptableAuthType("MyPolicy");

        String clientId = createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
        });

        try {
            assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());

            updateClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
                clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
            });
            assertEquals(JWTClientAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());

        } finally {
            deleteClientByAdmin(clientId);
        }
    }

    @Test
    public void testAdminClientRegisterDefaultAuthType() {
        setupPolicyAcceptableAuthType("MyPolicy");

        try {
            createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {});
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(Errors.INVALID_REGISTRATION, e.getMessage());
        }
    }

    @Test
    public void testAdminClientUpdateDefaultAuthType() throws ClientPolicyException {
        setupPolicyAcceptableAuthType("MyPolicy");

        String clientId = createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
        });

        try {
            assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());

            updateClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
                clientRep.setServiceAccountsEnabled(Boolean.FALSE);
            });
            assertEquals(JWTClientSecretAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());
            assertEquals(Boolean.FALSE, getClientByAdmin(clientId).isServiceAccountsEnabled());
        } finally {
            deleteClientByAdmin(clientId);
        }
    }

    @Test
    public void testAdminClientAugmentedAuthType() throws ClientPolicyException {
        setupPolicyAcceptableAuthType("MyPolicy");

        updateExecutor("SecureClientAuthEnforceExecutor", (ComponentRepresentation provider) -> {
            setExecutorAugmentActivate(provider);
            setExecutorAugmentedClientAuthMethod(provider, X509ClientAuthenticator.PROVIDER_ID);
        });

        String clientId = createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(ClientIdAndSecretAuthenticator.PROVIDER_ID);
        });

        try {
            assertEquals(X509ClientAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());

            updateExecutor("SecureClientAuthEnforceExecutor", (ComponentRepresentation provider) -> {
                setExecutorAugmentedClientAuthMethod(provider, JWTClientAuthenticator.PROVIDER_ID);
            });

            updateClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
                clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
            });
            assertEquals(JWTClientAuthenticator.PROVIDER_ID, getClientByAdmin(clientId).getClientAuthenticatorType());

        } finally {
            deleteClientByAdmin(clientId);
        }
    }

    @Test
    public void testDynamicClientRegisterAndUpdate() throws ClientRegistrationException {
        setupPolicyAcceptableAuthType("MyPolicy");

        String clientId = createClientDynamically("Gourmet-App", (OIDCClientRepresentation clientRep) -> {});
        try {
            assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, getClientDynamically(clientId).getTokenEndpointAuthMethod());
            assertEquals(Boolean.FALSE, getClientDynamically(clientId).getTlsClientCertificateBoundAccessTokens());

            updateClientDynamically(clientId, (OIDCClientRepresentation clientRep) -> {
                clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.CLIENT_SECRET_BASIC);
                clientRep.setTlsClientCertificateBoundAccessTokens(Boolean.TRUE);
            });
            assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, getClientDynamically(clientId).getTokenEndpointAuthMethod());
            assertEquals(Boolean.TRUE, getClientDynamically(clientId).getTlsClientCertificateBoundAccessTokens());

        } finally {
            deleteClientDynamically(clientId);
        }
    }

    @Test
    public void testAuthzCodeFlowUnderMultiPhasePolicy() throws Exception {
        setupPolicyAuthzCodeFlowUnderMultiPhasePolicy("MultiPhasePolicy");

        String userName = "test-user@localhost";
        String userPassword = "password";
        String clientName = "Flughafen-App";
        String clientId = createClientDynamically(clientName, (OIDCClientRepresentation clientRep) -> {});
        events.expect(EventType.CLIENT_REGISTER).client(clientId).user(Matchers.isEmptyOrNullString()).assertEvent();
        OIDCClientRepresentation response = getClientDynamically(clientId);
        String clientSecret = response.getClientSecret();
        assertEquals(clientName, response.getClientName());
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, response.getTokenEndpointAuthMethod());
        events.expect(EventType.CLIENT_INFO).client(clientId).user(Matchers.isEmptyOrNullString()).assertEvent();

        updateClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setDefaultRoles(Arrays.asList("sample-client-role").toArray(new String[1]));
        });

        successfulLoginAndLogoutWithPKCE(response.getClientId(), clientSecret, userName, userPassword);
    }

    @Test
    public void testCreateDeletePolicyRuntime() throws ClientRegistrationException {
        String clientId = createClientDynamically("Gourmet-App", (OIDCClientRepresentation clientRep) -> {});
        try {
            OIDCClientRepresentation clientRep = getClientDynamically(clientId);
            assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, clientRep.getTokenEndpointAuthMethod());
            events.expect(EventType.CLIENT_REGISTER).client(clientId).user(Matchers.isEmptyOrNullString()).assertEvent();
            events.expect(EventType.CLIENT_INFO).client(clientId).user(Matchers.isEmptyOrNullString()).assertEvent();
            updateClientByAdmin(clientId, (ClientRepresentation cr) -> {
                cr.setDefaultRoles((String[]) Arrays.asList("sample-client-role").toArray(new String[1]));
            });

            successfulLoginAndLogout(clientId, clientRep.getClientSecret());

            setupPolicyAuthzCodeFlowUnderMultiPhasePolicy("MyPolicy");

            failLoginByNotFollowingPKCE(clientId);

            deletePolicy("MyPolicy");
            logger.info("... Deleted Policy : MyPolicy");

            successfulLoginAndLogout(clientId, clientRep.getClientSecret());

        } finally {
            deleteClientDynamically(clientId);
        }
    }

    @Test
    public void testCreateUpdateDeleteConditionRuntime() throws ClientRegistrationException, ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createExecutor("PKCEEnforceExecutor", PKCEEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAugmentActivate(provider);
        });
        registerExecutor("PKCEEnforceExecutor", policyName);
        logger.info("... Registered Executor : PKCEEnforceExecutor");

        String clientId = "Zahlungs-App";
        String clientSecret = "secret";
        String cid = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setDefaultRoles((String[]) Arrays.asList("sample-client-role").toArray(new String[1]));
            clientRep.setSecret(clientSecret);
        });

        try {
            successfulLoginAndLogout(clientId, clientSecret);
 
            createCondition("ClientRolesCondition", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
                setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role")));
            });
            registerCondition("ClientRolesCondition", policyName);
            logger.info("... Registered Condition : ClientRolesCondition");

            failLoginByNotFollowingPKCE(clientId);

            updateCondition("ClientRolesCondition", (ComponentRepresentation provider) -> {
                setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("anothor-client-role")));
            });

            successfulLoginAndLogout(clientId, clientSecret);

            deleteCondition("ClientRolesCondition", policyName);

            successfulLoginAndLogout(clientId, clientSecret);

        } finally {
            deleteClientByAdmin(cid);
        }
    }

    @Test
    public void testCreateUpdateDeleteExecutorRuntime() throws ClientRegistrationException, ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("ClientRolesCondition", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role")));
        });
        registerCondition("ClientRolesCondition", policyName);
        logger.info("... Registered Condition : ClientRolesCondition");

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionRegistrationMethods(provider, new ArrayList<>(Arrays.asList(UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER)));
        });
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        String clientId = "Zahlungs-App";
        String clientSecret = "secret";
        String cid = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            String[] defaultRoles = {"sample-client-role"};
            clientRep.setDefaultRoles(defaultRoles);
            clientRep.setSecret(clientSecret);
        });

        try {
            successfulLoginAndLogout(clientId, clientSecret);
 
            createExecutor("PKCEEnforceExecutor", PKCEEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
                setExecutorAugmentDeactivate(provider);
            });
            registerExecutor("PKCEEnforceExecutor", policyName);
            logger.info("... Registered Executor : PKCEEnforceExecutor");

            failLoginByNotFollowingPKCE(clientId);

            updateExecutor("PKCEEnforceExecutor", (ComponentRepresentation provider) -> {
               setExecutorAugmentActivate(provider);
            });

            updateClientByAdmin(cid, (ClientRepresentation clientRep) -> {
                clientRep.setServiceAccountsEnabled(Boolean.FALSE);
            });
            assertEquals(false, getClientByAdmin(cid).isServiceAccountsEnabled());
            assertEquals(OAuth2Constants.PKCE_METHOD_S256, OIDCAdvancedConfigWrapper.fromClientRepresentation(getClientByAdmin(cid)).getPkceCodeChallengeMethod());

            deleteExecutor("PKCEEnforceExecutor", policyName);
            logger.info("... Deleted Executor : PKCEEnforceExecutor");

            updateClientByAdmin(cid, (ClientRepresentation clientRep) -> {
                OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep).setPkceCodeChallengeMethod(null);
            });
            assertEquals(null, OIDCAdvancedConfigWrapper.fromClientRepresentation(getClientByAdmin(cid)).getPkceCodeChallengeMethod());

            successfulLoginAndLogout(clientId, clientSecret);

        } finally {
            deleteClientByAdmin(cid);
        }

    }

    @Test
    public void testMultiplePolicies() throws ClientRegistrationException, ClientPolicyException {
        String policyAlphaName = "MyPolicy-alpha";
        createPolicy(policyAlphaName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyAlphaName);

        createCondition("ClientRolesCondition-alpha", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role-alpha")));
        });
        registerCondition("ClientRolesCondition-alpha", policyAlphaName);
        logger.info("... Registered Condition : ClientRolesCondition-alpha");

        createCondition("UpdatingClientSourceCondition-alpha", UpdatingClientSourceConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionRegistrationMethods(provider, new ArrayList<>(Arrays.asList(UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER)));
        });
        registerCondition("UpdatingClientSourceCondition-alpha", policyAlphaName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition-alpha");

        createExecutor("SecureClientAuthEnforceExecutor-alpha", SecureClientAuthEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAcceptedClientAuthMethods(provider, new ArrayList<>(Arrays.asList(ClientIdAndSecretAuthenticator.PROVIDER_ID)));
            setExecutorAugmentActivate(provider);
            setExecutorAugmentedClientAuthMethod(provider, ClientIdAndSecretAuthenticator.PROVIDER_ID);
        });
        registerExecutor("SecureClientAuthEnforceExecutor-alpha", policyAlphaName);
        logger.info("... Registered Executor : SecureClientAuthEnforceExecutor-alpha");

        String policyBetaName = "MyPolicy-beta";
        createPolicy(policyBetaName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyBetaName);

        createCondition("ClientRolesCondition-beta", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role-beta")));
        });
        registerCondition("ClientRolesCondition-beta", policyBetaName);
        logger.info("... Registered Condition : ClientRolesCondition-beta");

        createExecutor("PKCEEnforceExecutor-beta", PKCEEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAugmentActivate(provider);
        });
        registerExecutor("PKCEEnforceExecutor-beta", policyBetaName);
        logger.info("... Registered Executor : PKCEEnforceExecutor-beta");

        String clientAlphaId = "Alpha-App";
        String clientAlphaSecret = "secretAlpha";
        String cAlphaId = createClientByAdmin(clientAlphaId, (ClientRepresentation clientRep) -> {
            clientRep.setDefaultRoles((String[]) Arrays.asList("sample-client-role-alpha").toArray(new String[1]));
            clientRep.setSecret(clientAlphaSecret);
            clientRep.setClientAuthenticatorType(JWTClientSecretAuthenticator.PROVIDER_ID);
        });

        String clientBetaId = "Beta-App";
        String clientBetaSecret = "secretBeta";
        String cBetaId = createClientByAdmin(clientBetaId, (ClientRepresentation clientRep) -> {
            clientRep.setDefaultRoles((String[]) Arrays.asList("sample-client-role-beta").toArray(new String[1]));
            clientRep.setSecret(clientBetaSecret);
        });

        try {
            assertEquals(ClientIdAndSecretAuthenticator.PROVIDER_ID, getClientByAdmin(cAlphaId).getClientAuthenticatorType());

            successfulLoginAndLogout(clientAlphaId, clientAlphaSecret);

            failLoginByNotFollowingPKCE(clientBetaId);

        } finally {
            deleteClientByAdmin(cAlphaId);
            deleteClientByAdmin(cBetaId);
        }
    }

    @Test
    public void testIntentionalExceptionOnCondition() throws ClientRegistrationException, ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("TestRaiseExeptionCondition", TestRaiseExeptionConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
        });
        registerCondition("TestRaiseExeptionCondition", policyName);
        logger.info("... Registered Condition : TestRaiseExeptionCondition-beta");

        try {
            createClientByAdmin("Zahlungs-App", (ClientRepresentation clientRep) -> {
            });
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(Errors.INVALID_REGISTRATION, e.getMessage());
        }
    }

    @Test
    public void testClientIpAddressCondition() throws ClientRegistrationException, ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("ClientIpAddressCondition", ClientIpAddressConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientIpAddress(provider, new ArrayList<>(Arrays.asList("0.0.0.0", "127.0.0.1")));
        });
        registerCondition("ClientIpAddressCondition", policyName);
        logger.info("... Registered Condition : ClientIpAddressCondition");

        createExecutor("PKCEEnforceExecutor", PKCEEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAugmentDeactivate(provider);
        });
        registerExecutor("PKCEEnforceExecutor", policyName);
        logger.info("... Registered Executor : PKCEEnforceExecutor");

        String clientId = "Zahlungs-App";
        String clientSecret = "secret";
        String cid = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setSecret(clientSecret);
        });

        try { 
            failTokenRequestByNotFollowingPKCE(clientId, clientSecret);

            deleteExecutor("PKCEEnforceExecutor", policyName);
            logger.info("... Deleted Executor : PKCEEnforceExecutor");

            successfulLoginAndLogout(clientId, clientSecret);
        } finally {
            deleteClientByAdmin(cid);
        }
    }

    @Test
    public void testSecureSessionEnforceExecutor() throws ClientRegistrationException, ClientPolicyException {
        String policyBetaName = "MyPolicy-beta";
        createPolicy(policyBetaName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyBetaName);

        createCondition("ClientRolesCondition-beta", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role-beta")));
        });
        registerCondition("ClientRolesCondition-beta", policyBetaName);
        logger.info("... Registered Condition : ClientRolesCondition-beta");

        createExecutor("SecureSessionEnforceExecutor-beta", SecureSessionEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
        });
        registerExecutor("SecureSessionEnforceExecutor-beta", policyBetaName);
        logger.info("... Registered Executor : SecureSessionEnforceExecutor-beta");

        String clientAlphaId = "Alpha-App";
        String clientAlphaSecret = "secretAlpha";
        String cAlphaId = createClientByAdmin(clientAlphaId, (ClientRepresentation clientRep) -> {
            clientRep.setDefaultRoles((String[]) Arrays.asList("sample-client-role-alpha").toArray(new String[1]));
            clientRep.setSecret(clientAlphaSecret);
        });

        String clientBetaId = "Beta-App";
        String clientBetaSecret = "secretBeta";
        String cBetaId = createClientByAdmin(clientBetaId, (ClientRepresentation clientRep) -> {
            clientRep.setDefaultRoles((String[]) Arrays.asList("sample-client-role-beta").toArray(new String[1]));
            clientRep.setSecret(clientBetaSecret);
        });

        try {
            successfulLoginAndLogout(clientAlphaId, clientAlphaSecret);

            failLoginWithoutNonce(clientBetaId);

        } finally {
            deleteClientByAdmin(cAlphaId);
            deleteClientByAdmin(cBetaId);
        }
    }

    @Test
    public void testClientScopesCondition() throws ClientRegistrationException, ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("ClientScopesCondition", ClientScopesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientScopes(provider, new ArrayList<>(Arrays.asList("offline_access", "microprofile-jwt")));
        });
        registerCondition("ClientScopesCondition", policyName);
        logger.info("... Registered Condition : ClientScopesCondition");

        createExecutor("PKCEEnforceExecutor", PKCEEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAugmentActivate(provider);
        });
        registerExecutor("PKCEEnforceExecutor", policyName);
        logger.info("... Registered Executor : PKCEEnforceExecutor");

        String clientAlphaId = "Alpha-App";
        String clientAlphaSecret = "secretAlpha";
        String cAlphaId = createClientByAdmin(clientAlphaId, (ClientRepresentation clientRep) -> {
            clientRep.setSecret(clientAlphaSecret);
        });

        try {
            oauth.scope("address" + " " + "phone");
            successfulLoginAndLogout(clientAlphaId, clientAlphaSecret);

            oauth.scope("microprofile-jwt" + " " + "profile");
            failLoginByNotFollowingPKCE(clientAlphaId);

            successfulLoginAndLogoutWithPKCE(clientAlphaId, clientAlphaSecret, "test-user@localhost", "password");
        } catch (Exception e) {
            fail();
        } finally {
            deleteClientByAdmin(cAlphaId);
        }
    }

    @Test
    public void testSecureSigningAlgorithmEnforceExecutor() throws ClientRegistrationException, ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionRegistrationMethods(provider, new ArrayList<>(Arrays.asList(
                    UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER,
                    UpdatingClientSourceConditionFactory.BY_INITIAL_ACCESS_TOKEN,
                    UpdatingClientSourceConditionFactory.BY_REGISTRATION_ACCESS_TOKEN)));
        });
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createExecutor("SecureSigningAlgorithmEnforceExecutor", SecureSigningAlgorithmEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
        });
        registerExecutor("SecureSigningAlgorithmEnforceExecutor", policyName);
        logger.info("... Registered Executor : SecureSigningAlgorithmEnforceExecutor");

        String clientId = null;
        String cAlphaId = null;
        try {
            clientId = createClientDynamically("Gourmet-App", (OIDCClientRepresentation clientRep) -> {
                clientRep.setUserinfoSignedResponseAlg(Algorithm.ES256);
                clientRep.setRequestObjectSigningAlg(Algorithm.ES256);
                clientRep.setIdTokenSignedResponseAlg(Algorithm.PS256);
                clientRep.setTokenEndpointAuthSigningAlg(Algorithm.PS256);
            });
            events.expect(EventType.CLIENT_REGISTER).client(clientId).user(Matchers.isEmptyOrNullString()).assertEvent();
            getClientDynamically(clientId);

            cAlphaId = createClientByAdmin("Alpha-App", (ClientRepresentation clientRep) -> {
                clientRep.setAttributes(new HashMap<>());
                clientRep.getAttributes().put(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG, Algorithm.PS256);
                clientRep.getAttributes().put(OIDCConfigAttributes.REQUEST_OBJECT_SIGNATURE_ALG, Algorithm.ES256);
                clientRep.getAttributes().put(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG, Algorithm.ES256);
                clientRep.getAttributes().put(OIDCConfigAttributes.ACCESS_TOKEN_SIGNED_RESPONSE_ALG, Algorithm.ES256);
                clientRep.getAttributes().put(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, Algorithm.ES256);
            });

            try {
                createClientByAdmin("Beta-App", (ClientRepresentation clientRep) -> {
                    clientRep.setDefaultRoles((String[]) Arrays.asList("sample-client-role-beta").toArray(new String[1]));
                    clientRep.setSecret("secretBeta");
                });
                fail();
            } catch (ClientPolicyException e) {
                assertEquals(Errors.INVALID_REGISTRATION, e.getMessage());
            }

           try {
                updateClientDynamically(clientId, (OIDCClientRepresentation clientRep) -> {
                    clientRep.setIdTokenSignedResponseAlg(Algorithm.RS256);
                });
               fail();
            } catch (ClientRegistrationException e) {
                assertEquals("Failed to send request", e.getMessage());
            }
        } finally {
            deleteClientByAdmin(cAlphaId);
            deleteClientDynamically(clientId);
        }
    }

    @Test
    public void testSecureSigningAlgorithmForSignedJwtEnforceExecutor() throws Exception {
        // policy including client role condition
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("ClientRolesCondition", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role-alpha", "sample-client-role-zeta")));
        });
        registerCondition("ClientRolesCondition", policyName);
        logger.info("... Registered Condition : " + "ClientRolesCondition");

        createExecutor("SecureSigningAlgorithmForSignedJwtEnforceExecutor", SecureSigningAlgorithmForSignedJwtEnforceExecutorFactory.PROVIDER_ID, null,
                       (ComponentRepresentation provider) -> {
                       });

        registerExecutor("SecureSigningAlgorithmForSignedJwtEnforceExecutor", policyName);
        logger.info("... Registered Executor : SecureSigningAlgorithmForSignedJwtEnforceExecutor");

        // crate a client with client role
        String clientAlphaId = "Alpha-App";
        String clientAlphaSecret = "secretAlpha";
        String cAlphaId = null;

            cAlphaId = createClientByAdmin(clientAlphaId, (ClientRepresentation clientRep) -> {
                clientRep.setDefaultRoles(Arrays.asList("sample-client-role-alpha", "sample-client-role-common").toArray(new String[2]));
                clientRep.setSecret(clientAlphaSecret);
                clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
                clientRep.setAttributes(new HashMap<>());
                clientRep.getAttributes().put(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, Algorithm.ES256);
            });
        try {
            ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm(TEST_REALM_NAME), clientAlphaId);
            ClientRepresentation clientRep = clientResource.toRepresentation();

            KeyPair keyPair = setupJwks(Algorithm.ES256, clientRep, clientResource);
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            successfulLoginAndLogoutWithSignedJWT(clientAlphaId, privateKey, publicKey);
        } finally {
            deleteClientByAdmin(cAlphaId);
        }
    }

    private CloseableHttpResponse sendRequest(String requestUrl, List<NameValuePair> parameters) throws Exception {
        CloseableHttpClient client = new DefaultHttpClient();
        try {
            HttpPost post = new HttpPost(requestUrl);
            UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, "UTF-8");
            post.setEntity(formEntity);
            return client.execute(post);
        } finally {
            oauth.closeClient(client);
        }
    }

    @Test
    public void testClientDisabledClientEnforceExecutor() throws ClientPolicyException, ClientRegistrationException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null,
                        (ComponentRepresentation provider) ->
                                setConditionRegistrationMethods(provider, Arrays.asList(
                                        UpdatingClientSourceConditionFactory.BY_ANONYMOUS,
                                        UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER,
                                        UpdatingClientSourceConditionFactory.BY_INITIAL_ACCESS_TOKEN,
                                        UpdatingClientSourceConditionFactory.BY_REGISTRATION_ACCESS_TOKEN
                                )));
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createExecutor("ClientDisabledClientEnforceExecutor", ClientDisabledClientEnforceExecutorFactory.PROVIDER_ID, null,
                       (ComponentRepresentation provider) -> {
                       });
        registerExecutor("ClientDisabledClientEnforceExecutor", policyName);
        logger.info("... Registered Executor : ClientDisabledClientEnforceExecutor");

        //client by admin
        String cAlphaId = null;
        try {
            cAlphaId = createClientByAdmin("Alpha-disabled-App", (ClientRepresentation clientRep) -> {
            });
            ClientRepresentation clientByAdmin = getClientByAdmin(cAlphaId);
            assertFalse(clientByAdmin.isEnabled());

            try {
                updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
                    clientRep.setEnabled(true);
                });
                fail();
            } catch (BadRequestException e) {
                assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatus());
            }

            // Try to update disabled client. Should pass
            updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
                clientRep.setEnabled(false);
            });
        } finally {
            deleteClientByAdmin(cAlphaId);
        }

        //dynamic client
        String cBettaId = null;
        try {
            cBettaId = createClientDynamically("Betta-disabled-App", (OIDCClientRepresentation clientRep) -> {
            });
            ClientRepresentation clientRep = reg.get(cBettaId);
            assertFalse(clientRep.isEnabled());

            try {
                // Try to enable client. Should fail
                clientRep.setEnabled(true);
                reg.update(clientRep);
                fail();
            } catch (ClientRegistrationException e) {
                assertEquals("Failed to send request", e.getMessage());
            }
            // Try to update disabled client. Should pass
            clientRep.setEnabled(false);
            reg.update(clientRep);
        } finally {
            deleteClientByAdmin(cBettaId);
        }
    }

    @Test
    public void testConsentRequiredClientEnforceExecutor() throws ClientPolicyException, ClientRegistrationException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null,
                        (ComponentRepresentation provider) ->
                                setConditionRegistrationMethods(provider, Arrays.asList(
                                        UpdatingClientSourceConditionFactory.BY_ANONYMOUS,
                                        UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER,
                                        UpdatingClientSourceConditionFactory.BY_INITIAL_ACCESS_TOKEN,
                                        UpdatingClientSourceConditionFactory.BY_REGISTRATION_ACCESS_TOKEN
                                )));
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createExecutor("ConsentRequiredClientEnforceExecutor", ConsentRequiredClientEnforceExecutorFactory.PROVIDER_ID, null,
                       (ComponentRepresentation provider) -> {
                       });
        registerExecutor("ConsentRequiredClientEnforceExecutor", policyName);
        logger.info("... Registered Executor : ConsentRequiredClientEnforceExecutor");

        //client by admin
        String cAlphaId = null;
        try {
            cAlphaId = createClientByAdmin("Alpha-consentRequired-App", (ClientRepresentation clientRep) -> {
            });
            ClientRepresentation clientByAdmin = getClientByAdmin(cAlphaId);
            assertTrue(clientByAdmin.isConsentRequired());

            try {
                updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
                    clientRep.setConsentRequired(false);
                });
                fail();
            } catch (BadRequestException e) {
                assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatus());
            }

            // Try to update consentRequired of client. Should pass
            updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
                clientRep.setConsentRequired(true);
            });
        } finally {
            deleteClientByAdmin(cAlphaId);
        }

        //dynamic client
        String cBettaId = null;
        try {
            cBettaId = createClientDynamically("Betta-consentRequired-App", (OIDCClientRepresentation clientRep) -> {
            });
            ClientRepresentation clientRep = reg.get(cBettaId);
            assertTrue(clientRep.isConsentRequired());

            try {
                // Try to setConsentRequired client. Should fail
                clientRep.setConsentRequired(false);
                reg.update(clientRep);
                fail();
            } catch (ClientRegistrationException e) {
                assertEquals("Failed to send request", e.getMessage());
            }
            // Try to setConsentRequired client. Should pass
            clientRep.setConsentRequired(true);
            reg.update(clientRep);
        } finally {
            deleteClientByAdmin(cBettaId);
        }
    }

    @Test
    public void testScopeClientRegistrationEnforceExecutor() throws ClientPolicyException, ClientRegistrationException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null,
                        (ComponentRepresentation provider) ->
                                setConditionRegistrationMethods(provider, Arrays.asList(
                                        UpdatingClientSourceConditionFactory.BY_ANONYMOUS,
                                        UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER,
                                        UpdatingClientSourceConditionFactory.BY_INITIAL_ACCESS_TOKEN,
                                        UpdatingClientSourceConditionFactory.BY_REGISTRATION_ACCESS_TOKEN
                                )));
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createExecutor("ScopeClientRegistrationEnforceExecutor", ScopeClientRegistrationEnforceExecutorFactory.PROVIDER_ID, null,
                       (ComponentRepresentation provider) -> {
                       });
        registerExecutor("ScopeClientRegistrationEnforceExecutor", policyName);
        logger.info("... Registered Executor : ScopeClientRegistrationEnforceExecutor");

        //client by admin
        String cAlphaId = null;
        try {
            cAlphaId = createClientByAdmin("Alpha-fullScopeAllowed-App", (ClientRepresentation clientRep) -> {
            });
            ClientRepresentation clientByAdmin = getClientByAdmin(cAlphaId);
            assertFalse(clientByAdmin.isFullScopeAllowed());

            try {
                updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
                    clientRep.setFullScopeAllowed(true);
                });
                fail();
            } catch (BadRequestException e) {
                assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatus());
            }

            // Try to update consentRequired of client. Should pass
            updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
                clientRep.setFullScopeAllowed(false);
            });
        } finally {
            deleteClientByAdmin(cAlphaId);
        }

        //dynamic client
        String cBettaId = null;
        try {
            cBettaId = createClientDynamically("Betta-fullScopeAllowed-App", (OIDCClientRepresentation clientRep) -> {
            });
            ClientRepresentation clientRep = reg.get(cBettaId);
            assertFalse(clientRep.isFullScopeAllowed());

            try {
                // Try to setFullScopeAllowed client. Should fail
                clientRep.setFullScopeAllowed(true);
                reg.update(clientRep);
                fail();
            } catch (ClientRegistrationException e) {
                assertEquals("Failed to send request", e.getMessage());
            }
            // Try to setFullScopeAllowed client. Should pass
            clientRep.setFullScopeAllowed(false);
            reg.update(clientRep);
        } finally {
            deleteClientByAdmin(cBettaId);
        }
    }

    @Test
    public void testProtocolMappersClientEnforceExecutor() throws ClientPolicyException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null,
                        (ComponentRepresentation provider) ->
                                setConditionRegistrationMethods(provider, Arrays.asList(
                                        UpdatingClientSourceConditionFactory.BY_ANONYMOUS,
                                        UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER,
                                        UpdatingClientSourceConditionFactory.BY_INITIAL_ACCESS_TOKEN,
                                        UpdatingClientSourceConditionFactory.BY_REGISTRATION_ACCESS_TOKEN
                                )));
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createExecutor("ProtocolMappersClientEnforceExecutor", ProtocolMappersClientEnforceExecutorFactory.PROVIDER_ID, null,
                       (ComponentRepresentation provider) -> {
                       });
        registerExecutor("ProtocolMappersClientEnforceExecutor", policyName);
        logger.info("... Registered Executor : ProtocolMappersClientEnforceExecutor");

        //client by admin
        String cAlphaId = null;
        try {
            try {
            createClientByAdmin("Alpha-protocolMappers-App", (ClientRepresentation clientRep) -> {
                clientRep.setProtocolMappers(Collections.singletonList(createHardcodedMapperRep()));
            });
            } catch (ClientPolicyException e) {
                assertEquals(Errors.INVALID_REGISTRATION, e.getMessage());
            }

            updateExecutor("ProtocolMappersClientEnforceExecutor", (ComponentRepresentation provider) -> {
                provider.getConfig().add(ProtocolMappersClientEnforceExecutorFactory.ALLOWED_PROTOCOL_MAPPER_TYPES, "oidc-hardcoded-role-mapper");
            });

            cAlphaId = createClientByAdmin("Alpha-protocolMappers-App", (ClientRepresentation clientRep) -> {
                clientRep.setProtocolMappers(Collections.singletonList(createHardcodedMapperRep()));
            });
            assertNotNull(cAlphaId);

            ClientRepresentation clientByAdmin = getClientByAdmin(cAlphaId);
            assertEquals(1, clientByAdmin.getProtocolMappers().size());

            updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {});
        } finally {
            deleteClientByAdmin(cAlphaId);
        }
    }

    @Test
    public void testTrustedHostClientEnforceExecutor() throws ClientPolicyException, ClientRegistrationException {
        String policyName = "MyPolicy";
        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null,
                        (ComponentRepresentation provider) ->
                                setConditionRegistrationMethods(provider, Arrays.asList(
                                        UpdatingClientSourceConditionFactory.BY_ANONYMOUS,
                                        UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER,
                                        UpdatingClientSourceConditionFactory.BY_INITIAL_ACCESS_TOKEN,
                                        UpdatingClientSourceConditionFactory.BY_REGISTRATION_ACCESS_TOKEN
                                )));
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createExecutor("TrustedHostClientEnforceExecutor", TrustedHostClientEnforceExecutorFactory.PROVIDER_ID, null,
                       (ComponentRepresentation provider) -> {
                           provider.getConfig().putSingle(TrustedHostClientEnforceExecutorFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH, "false");
                           provider.getConfig().putSingle(TrustedHostClientEnforceExecutorFactory.CLIENT_URIS_MUST_MATCH, "true");
                           provider.getConfig().put(TrustedHostClientEnforceExecutorFactory.TRUSTED_HOSTS, Arrays.asList("localhost", "www.host.com", "*.example.com"));
                       });
        registerExecutor("TrustedHostClientEnforceExecutor", policyName);
        logger.info("... Registered Executor : TrustedHostClientEnforceExecutor");

        //client by admin
        String cAlphaId = createClientByAdmin("Alpha-trustedHost-App", (ClientRepresentation clientRep) -> {
            clientRep.setBaseUrl("http://www.host.com");
            clientRep.setRedirectUris(Collections.singletonList("http://www.example.com"));
        });
        assertNotNull(cAlphaId);

        ClientRepresentation clientByAdmin = getClientByAdmin(cAlphaId);
        assertEquals("http://www.host.com", clientByAdmin.getBaseUrl());
        assertEquals(Collections.singletonList("http://www.example.com"), clientByAdmin.getRedirectUris());
        updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
        });

        try {
            updateClientByAdmin(cAlphaId, (ClientRepresentation clientRep) -> {
                clientRep.setBaseUrl("http://www.host.com1");
                clientRep.setRedirectUris(Collections.singletonList("http://www.example.com1"));
            });
            fail();
        } catch (BadRequestException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatus());
        }

        deleteClientByAdmin(cAlphaId);

        //dynamic client
        String cBettaId = createClientDynamically("Betta-trustedHost-App", (OIDCClientRepresentation clientRep) -> {
            clientRep.setRedirectUris(Collections.singletonList("http://www.example.com"));
        });
        assertNotNull(cBettaId);

        OIDCClientRepresentation clientDynamically = getClientDynamically(cBettaId);
        assertEquals(Collections.singletonList("http://www.example.com"), clientDynamically.getRedirectUris());
        updateClientByAdmin(cBettaId, (ClientRepresentation clientRep) -> {
        });

        try {
            updateClientDynamically(cBettaId, (OIDCClientRepresentation clientRep) -> {
                clientRep.setRedirectUris(Collections.singletonList("http://www.example.com1"));
            });
            fail();
        } catch (ClientRegistrationException e) {
            assertEquals("Failed to send request", e.getMessage());
        }

        deleteClientByAdmin(cBettaId);
    }

    private ProtocolMapperRepresentation createHardcodedMapperRep() {
        ProtocolMapperRepresentation protocolMapper = new ProtocolMapperRepresentation();
        protocolMapper.setName("Hardcoded foo role");
        protocolMapper.setProtocolMapper(HardcodedRole.PROVIDER_ID);
        protocolMapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        protocolMapper.getConfig().put(HardcodedRole.ROLE_CONFIG, "foo-role");
        return protocolMapper;
    }

    private void checkMtlsFlow(String password) throws IOException {
        ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), "test-app");
        ClientRepresentation clientRep = clientResource.toRepresentation();
        clientRep.setDefaultRoles(new String[]{"sample-client-role"});
        OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep).setUseMtlsHoKToken(true);

        clientResource.update(clientRep);

        // Check login.
        OAuthClient.AuthorizationEndpointResponse loginResponse = oauth.doLogin("test-user@localhost", password);
        Assert.assertNull(loginResponse.getError());

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        // Check token obtaining.
        OAuthClient.AccessTokenResponse accessTokenResponse;
        try (CloseableHttpClient client = MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore()) {
            accessTokenResponse = oauth.doAccessTokenRequest(code, password, client);
        }  catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        assertEquals(200, accessTokenResponse.getStatusCode());

        // Check token refresh.
        OAuthClient.AccessTokenResponse accessTokenResponseRefreshed;
        try (CloseableHttpClient client = MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore()) {
            accessTokenResponseRefreshed = oauth.doRefreshTokenRequest(accessTokenResponse.getRefreshToken(), password, client);
        }  catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        assertEquals(200, accessTokenResponseRefreshed.getStatusCode());

        // Check token introspection.
        String tokenResponse;
        try (CloseableHttpClient client = MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore()) {
            tokenResponse = oauth.introspectTokenWithClientCredential(TEST_CLIENT, password, "access_token", accessTokenResponse.getAccessToken(), client);
        }  catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        Assert.assertNotNull(tokenResponse);
        TokenMetadataRepresentation tokenMetadataRepresentation = JsonSerialization.readValue(tokenResponse, TokenMetadataRepresentation.class);
        assertTrue(tokenMetadataRepresentation.isActive());

        // Check token revoke.
        CloseableHttpResponse tokenRevokeResponse;
        try (CloseableHttpClient client = MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore()) {
            tokenRevokeResponse = oauth.doTokenRevoke(accessTokenResponse.getRefreshToken(), "refresh_token", password, client);
        }  catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        assertEquals(200, tokenRevokeResponse.getStatusLine().getStatusCode());

        // Check logout.
        CloseableHttpResponse logoutResponse;
        try (CloseableHttpClient client = MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore()) {
            logoutResponse = oauth.doLogout(accessTokenResponse.getRefreshToken(), password, client);
        }  catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        assertEquals(204, logoutResponse.getStatusLine().getStatusCode());
    }

    private void setupPolicyAcceptableAuthType(String policyName) {

        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionRegistrationMethods(provider, new ArrayList<>(Arrays.asList(UpdatingClientSourceConditionFactory.BY_AUTHENTICATED_USER)));
        });
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createExecutor("SecureClientAuthEnforceExecutor", SecureClientAuthEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAcceptedClientAuthMethods(provider, new ArrayList<>(Arrays.asList(
                    JWTClientAuthenticator.PROVIDER_ID, JWTClientSecretAuthenticator.PROVIDER_ID, X509ClientAuthenticator.PROVIDER_ID)));
        });
        registerExecutor("SecureClientAuthEnforceExecutor", policyName);
        logger.info("... Registered Executor : SecureClientAuthEnforceExecutor");

    }

    private void setupPolicyAuthzCodeFlowUnderMultiPhasePolicy(String policyName) {

        logger.info("Setup Policy");

        createPolicy(policyName, DefaultClientPolicyProviderFactory.PROVIDER_ID, null, null, null);
        logger.info("... Created Policy : " + policyName);

        createCondition("UpdatingClientSourceCondition", UpdatingClientSourceConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionRegistrationMethods(provider, new ArrayList<>(Arrays.asList(UpdatingClientSourceConditionFactory.BY_INITIAL_ACCESS_TOKEN)));
        });
        registerCondition("UpdatingClientSourceCondition", policyName);
        logger.info("... Registered Condition : UpdatingClientSourceCondition");

        createCondition("ClientRolesCondition", ClientRolesConditionFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setConditionClientRoles(provider, new ArrayList<>(Arrays.asList("sample-client-role")));
        });
        registerCondition("ClientRolesCondition", policyName);
        logger.info("... Registered Condition : ClientRolesCondition");

        createExecutor("SecureClientAuthEnforceExecutor", SecureClientAuthEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAcceptedClientAuthMethods(provider, new ArrayList<>(Arrays.asList(ClientIdAndSecretAuthenticator.PROVIDER_ID, JWTClientAuthenticator.PROVIDER_ID)));
            setExecutorAugmentedClientAuthMethod(provider, ClientIdAndSecretAuthenticator.PROVIDER_ID);
            setExecutorAugmentActivate(provider);
        });
        registerExecutor("SecureClientAuthEnforceExecutor", policyName);
        logger.info("... Registered Executor : SecureClientAuthEnforceExecutor");

        createExecutor("PKCEEnforceExecutor", PKCEEnforceExecutorFactory.PROVIDER_ID, null, (ComponentRepresentation provider) -> {
            setExecutorAugmentActivate(provider);
        });
        registerExecutor("PKCEEnforceExecutor", policyName);
        logger.info("... Registered Executor : PKCEEnforceExecutor");

    }

    private void successfulLoginAndLogout(String clientId, String clientSecret) {
        oauth.clientId(clientId);
        oauth.doLogin("test-user@localhost", "password");

        EventRepresentation loginEvent = events.expectLogin().client(clientId).assertEvent();
        String sessionId = loginEvent.getSessionId();
        String codeId = loginEvent.getDetails().get(Details.CODE_ID);
        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        OAuthClient.AccessTokenResponse res = oauth.doAccessTokenRequest(code, clientSecret);
        assertEquals(200, res.getStatusCode());
        events.expectCodeToToken(codeId, sessionId).client(clientId).assertEvent();

        oauth.doLogout(res.getRefreshToken(), clientSecret);
        events.expectLogout(sessionId).client(clientId).clearDetails().assertEvent();
    }

    private void successfulLoginAndLogoutWithSignedJWT(String clientId, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        String signedJwt = createSignedRequestToken(clientId, getRealmInfoUrl(), privateKey, publicKey, Algorithm.ES256);

        oauth.clientId(clientId);
        oauth.doLogin("test-user@localhost", "password");
        EventRepresentation loginEvent = events.expectLogin()
                                                 .client(clientId)
                                                 .assertEvent();
        String sessionId = loginEvent.getSessionId();
        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        //obtain access token
        OAuthClient.AccessTokenResponse response  = doAccessTokenRequestWithSignedJWT(code, signedJwt);

        assertEquals(200, response.getStatusCode());
        oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
        assertEquals(sessionId, refreshToken.getSessionState());
        assertEquals(sessionId, refreshToken.getSessionState());
        events.expectCodeToToken(loginEvent.getDetails().get(Details.CODE_ID), loginEvent.getSessionId())
                .client(clientId)
                .detail(Details.CLIENT_AUTH_METHOD, JWTClientAuthenticator.PROVIDER_ID)
                .assertEvent();

        //refresh token
        signedJwt = createSignedRequestToken(clientId, getRealmInfoUrl(), privateKey, publicKey, Algorithm.ES256);
        OAuthClient.AccessTokenResponse refreshedResponse = doRefreshTokenRequestWithSignedJWT(response.getRefreshToken(), signedJwt);
        assertEquals(200, refreshedResponse.getStatusCode());

        //introspect token
        signedJwt = createSignedRequestToken(clientId, getRealmInfoUrl(), privateKey, publicKey, Algorithm.ES256);
        HttpResponse tokenIntrospectionResponse = doTokenIntrospectionWithSignedJWT("access_token", refreshedResponse.getAccessToken(), signedJwt);
        assertEquals(200, tokenIntrospectionResponse.getStatusLine().getStatusCode());

        //revoke token
        signedJwt = createSignedRequestToken(clientId, getRealmInfoUrl(), privateKey, publicKey, Algorithm.ES256);
        HttpResponse revokeTokenResponse = doTokenRevokeWithSignedJWT("refresh_toke", refreshedResponse.getRefreshToken(), signedJwt);
        assertEquals(200, revokeTokenResponse.getStatusLine().getStatusCode());

        signedJwt = createSignedRequestToken(clientId, getRealmInfoUrl(), privateKey, publicKey, Algorithm.ES256);
        OAuthClient.AccessTokenResponse tokenRes = doRefreshTokenRequestWithSignedJWT(refreshedResponse.getRefreshToken(), signedJwt);
        assertEquals(400, tokenRes.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_GRANT, tokenRes.getError());

        //logout
        signedJwt = createSignedRequestToken(clientId, getRealmInfoUrl(), privateKey, publicKey, Algorithm.ES256);
        HttpResponse logoutResponse = doLogoutWithSignedJWT(refreshedResponse.getRefreshToken(), signedJwt);
        assertEquals(204, logoutResponse.getStatusLine().getStatusCode());

    }

    private KeyPair setupJwks(String algorithm, ClientRepresentation clientRepresentation, ClientResource clientResource) throws Exception {
        // generate and register client keypair
        TestOIDCEndpointsApplicationResource oidcClientEndpointsResource = testingClient.testApp().oidcClientEndpoints();
        oidcClientEndpointsResource.generateKeys(algorithm);
        Map<String, String> generatedKeys = oidcClientEndpointsResource.getKeysAsBase64();
        KeyPair keyPair = getKeyPairFromGeneratedBase64(generatedKeys, algorithm);

        // use and set jwks_url
        OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRepresentation).setUseJwksUrl(true);
        String jwksUrl = TestApplicationResourceUrls.clientJwksUri();
        OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRepresentation).setJwksUrl(jwksUrl);
        clientResource.update(clientRepresentation);

        // set time offset, so that new keys are downloaded
        setTimeOffset(20);

        return keyPair;
    }

    private KeyPair getKeyPairFromGeneratedBase64(Map<String, String> generatedKeys, String algorithm) throws Exception {
        // It seems that PemUtils.decodePrivateKey, decodePublicKey can only treat RSA type keys, not EC type keys. Therefore, these are not used.
        String privateKeyBase64 = generatedKeys.get(TestingOIDCEndpointsApplicationResource.PRIVATE_KEY);
        String publicKeyBase64 =  generatedKeys.get(TestingOIDCEndpointsApplicationResource.PUBLIC_KEY);
        PrivateKey privateKey = decodePrivateKey(Base64.decode(privateKeyBase64), algorithm);
        PublicKey publicKey = decodePublicKey(Base64.decode(publicKeyBase64), algorithm);
        return new KeyPair(publicKey, privateKey);
    }

    private static PrivateKey decodePrivateKey(byte[] der, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        String keyAlg = getKeyAlgorithmFromJwaAlgorithm(algorithm);
        KeyFactory kf = KeyFactory.getInstance(keyAlg, "BC");
        return kf.generatePrivate(spec);
    }

    private static PublicKey decodePublicKey(byte[] der, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        String keyAlg = getKeyAlgorithmFromJwaAlgorithm(algorithm);
        KeyFactory kf = KeyFactory.getInstance(keyAlg, "BC");
        return kf.generatePublic(spec);
    }

    private String createSignedRequestToken(String clientId, String realmInfoUrl, PrivateKey privateKey, PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JsonWebToken jwt = createRequestToken(clientId, realmInfoUrl);
        String kid = KeyUtils.createKeyId(publicKey);
        SignatureSignerContext signer = oauth.createSigner(privateKey, kid, algorithm);
        return new JWSBuilder().kid(kid).jsonContent(jwt).sign(signer);
    }

    private OAuthClient.AccessTokenResponse doAccessTokenRequestWithSignedJWT(String code, String signedJwt) throws Exception {
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CODE, code));
        parameters.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, oauth.getRedirectUri()));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION, signedJwt));

        CloseableHttpResponse response = sendRequest(oauth.getAccessTokenUrl(), parameters);
        return new OAuthClient.AccessTokenResponse(response);
    }

    private OAuthClient.AccessTokenResponse doRefreshTokenRequestWithSignedJWT(String refreshToken, String signedJwt) throws Exception {
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN));
        parameters.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, refreshToken));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION, signedJwt));

        CloseableHttpResponse response = sendRequest(oauth.getRefreshTokenUrl(), parameters);
        return new OAuthClient.AccessTokenResponse(response);
    }

    private HttpResponse doTokenIntrospectionWithSignedJWT(String tokenType, String tokenToIntrospect, String signedJwt) throws Exception {
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair("token", tokenToIntrospect));
        parameters.add(new BasicNameValuePair("token_type_hint", tokenType));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION, signedJwt));

        return sendRequest(oauth.getTokenIntrospectionUrl(), parameters);
    }

    private HttpResponse doTokenRevokeWithSignedJWT(String tokenType, String tokenToIntrospect, String signedJwt) throws Exception {
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair("token", tokenToIntrospect));
        parameters.add(new BasicNameValuePair("token_type_hint", tokenType));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION, signedJwt));

        return sendRequest(oauth.getTokenRevocationUrl(), parameters);
    }

    private HttpResponse doLogoutWithSignedJWT(String refreshToken, String signedJwt) throws Exception {
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN));
        parameters.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, refreshToken));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION, signedJwt));

        return sendRequest(oauth.getLogoutUrl().build(), parameters);
    }

    private JsonWebToken createRequestToken(String clientId, String realmInfoUrl) {
        JsonWebToken reqToken = new JsonWebToken();
        reqToken.id(AdapterUtils.generateId());
        reqToken.issuer(clientId);
        reqToken.subject(clientId);
        reqToken.audience(realmInfoUrl);

        int now = Time.currentTime();
        reqToken.issuedAt(now);
        reqToken.expiration(now + 10);
        reqToken.notBefore(now);

        return reqToken;
    }

    private static String getKeyAlgorithmFromJwaAlgorithm(String jwaAlgorithm) {
        String keyAlg = null;
        switch (jwaAlgorithm) {
            case Algorithm.RS256:
            case Algorithm.RS384:
            case Algorithm.RS512:
            case Algorithm.PS256:
            case Algorithm.PS384:
            case Algorithm.PS512:
                keyAlg = KeyType.RSA;
                break;
            case Algorithm.ES256:
            case Algorithm.ES384:
            case Algorithm.ES512:
                keyAlg = KeyType.EC;
                break;
            default :
                throw new RuntimeException("Unsupported signature algorithm");
        }
        return keyAlg;
    }

    private String getRealmInfoUrl() {
        String authServerBaseUrl = UriUtils.getOrigin(oauth.getRedirectUri()) + "/auth";
        return KeycloakUriBuilder.fromUri(authServerBaseUrl).path(ServiceUrlConstants.REALM_INFO_PATH).build(TEST_REALM_NAME).toString();
    }

    private void successfulLoginAndLogoutWithPKCE(String clientId, String clientSecret, String userName, String userPassword) throws Exception {
        oauth.clientId(clientId);
        String codeVerifier = "1a345A7890123456r8901c3456789012b45K7890l23"; // 43
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        oauth.codeChallenge(codeChallenge);
        oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        oauth.nonce("bjapewiziIE083d");

        oauth.doLogin(userName, userPassword);

        EventRepresentation loginEvent = events.expectLogin().client(clientId).assertEvent();
        String sessionId = loginEvent.getSessionId();
        String codeId = loginEvent.getDetails().get(Details.CODE_ID);
        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.codeVerifier(codeVerifier);

        OAuthClient.AccessTokenResponse res = oauth.doAccessTokenRequest(code, clientSecret);

        assertEquals(200, res.getStatusCode());
        events.expectCodeToToken(codeId, sessionId).client(clientId).assertEvent();

        AccessToken token = oauth.verifyToken(res.getAccessToken());

        String userId = findUserByUsername(adminClient.realm(REALM_NAME), userName).getId();
        assertEquals(userId, token.getSubject());
        Assert.assertNotEquals(userName, token.getSubject());
        assertEquals(sessionId, token.getSessionState());
        assertEquals(clientId, token.getIssuedFor());

        String refreshTokenString = res.getRefreshToken();
        RefreshToken refreshToken = oauth.parseRefreshToken(refreshTokenString);
        assertEquals(sessionId, refreshToken.getSessionState());
        assertEquals(clientId, refreshToken.getIssuedFor());

        OAuthClient.AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(refreshTokenString, clientSecret);
        assertEquals(200, refreshResponse.getStatusCode());

        AccessToken refreshedToken = oauth.verifyToken(refreshResponse.getAccessToken());
        RefreshToken refreshedRefreshToken = oauth.parseRefreshToken(refreshResponse.getRefreshToken());
        assertEquals(sessionId, refreshedToken.getSessionState());
        assertEquals(sessionId, refreshedRefreshToken.getSessionState());

        assertEquals(findUserByUsername(adminClient.realm(REALM_NAME), userName).getId(), refreshedToken.getSubject());

        events.expectRefresh(refreshToken.getId(), sessionId).client(clientId).assertEvent();

        doIntrospectAccessToken(refreshResponse, userName, clientId, clientSecret);

        doTokenRevoke(refreshResponse.getRefreshToken(), clientId, clientSecret, userId, false);
    }

    private void failLoginWithoutSecureResponseType(String clientId) {
        oauth.clientId(clientId);
        oauth.openLoginForm();
        assertEquals(OAuthErrorException.INVALID_REQUEST, oauth.getCurrentQuery().get(OAuth2Constants.ERROR));
        assertEquals("invalid response_type", oauth.getCurrentQuery().get(OAuth2Constants.ERROR_DESCRIPTION));
    }

    private void failLoginWithoutNonce(String clientId) {
        oauth.clientId(clientId);
        oauth.openLoginForm();
        assertEquals(OAuthErrorException.INVALID_REQUEST, oauth.getCurrentQuery().get(OAuth2Constants.ERROR));
        assertEquals("Missing parameter: nonce", oauth.getCurrentQuery().get(OAuth2Constants.ERROR_DESCRIPTION));
    }

    private void failLoginByNotFollowingPKCE(String clientId) {
        oauth.clientId(clientId);
        oauth.openLoginForm();
        assertEquals(OAuthErrorException.INVALID_REQUEST, oauth.getCurrentQuery().get(OAuth2Constants.ERROR));
        assertEquals("Missing parameter: code_challenge_method", oauth.getCurrentQuery().get(OAuth2Constants.ERROR_DESCRIPTION));
    }

    private void failTokenRequestByNotFollowingPKCE(String clientId, String clientSecret) {
        oauth.clientId(clientId);
        oauth.doLogin("test-user@localhost", "password");

        EventRepresentation loginEvent = events.expectLogin().client(clientId).assertEvent();
        String sessionId = loginEvent.getSessionId();
        String codeId = loginEvent.getDetails().get(Details.CODE_ID);
        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        OAuthClient.AccessTokenResponse res = oauth.doAccessTokenRequest(code, clientSecret);

        assertEquals(OAuthErrorException.INVALID_GRANT, res.getError());
        assertEquals("PKCE code verifier not specified", res.getErrorDescription());
        events.expect(EventType.CODE_TO_TOKEN_ERROR).client(clientId).session(sessionId).clearDetails().error(Errors.CODE_VERIFIER_MISSING).assertEvent();

        oauth.openLogout();

        events.expectLogout(sessionId).clearDetails().assertEvent();
    }

    private String generateS256CodeChallenge(String codeVerifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(codeVerifier.getBytes("ISO_8859_1"));
        byte[] digestBytes = md.digest();
        String codeChallenge = Base64Url.encode(digestBytes);
        return codeChallenge;
    }

    private void doIntrospectAccessToken(OAuthClient.AccessTokenResponse tokenRes, String username, String clientId, String clientSecret) throws IOException {
        String tokenResponse = oauth.introspectAccessTokenWithClientCredential(clientId, clientSecret, tokenRes.getAccessToken());
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(tokenResponse);
        assertEquals(true, jsonNode.get("active").asBoolean());
        assertEquals(username, jsonNode.get("username").asText());
        assertEquals(clientId, jsonNode.get("client_id").asText());
        TokenMetadataRepresentation rep = objectMapper.readValue(tokenResponse, TokenMetadataRepresentation.class);
        assertEquals(true, rep.isActive());
        assertEquals(clientId, rep.getClientId());
        assertEquals(clientId, rep.getIssuedFor());
        events.expect(EventType.INTROSPECT_TOKEN).client(clientId).user((String)null).clearDetails().assertEvent();
    }

    private void doTokenRevoke(String refreshToken, String clientId, String clientSecret, String userId, boolean isOfflineAccess) throws IOException {
        oauth.clientId(clientId);
        oauth.doTokenRevoke(refreshToken, "refresh_token", clientSecret);

        // confirm revocation
        OAuthClient.AccessTokenResponse tokenRes = oauth.doRefreshTokenRequest(refreshToken, clientSecret);
        assertEquals(400, tokenRes.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_GRANT, tokenRes.getError());
        if (isOfflineAccess) assertEquals("Offline user session not found", tokenRes.getErrorDescription());
        else assertEquals("Session not active", tokenRes.getErrorDescription());

        events.expect(EventType.REVOKE_GRANT).clearDetails().client(clientId).user(userId).assertEvent();
    }

    private ComponentRepresentation createComponentInstance(String name, String providerId, String providerType, String subType) {
        ComponentRepresentation rep = new ComponentRepresentation();
        rep.setId(org.keycloak.models.utils.KeycloakModelUtils.generateId());
        rep.setName(name);
        rep.setParentId(REALM_NAME);
        rep.setProviderId(providerId);
        rep.setProviderType(providerType);
        rep.setSubType(subType);
        rep.setConfig(new MultivaluedHashMap<>());
        return rep;
    }

    private String createComponent(ComponentRepresentation cr) {
        Response resp = adminClient.realm(REALM_NAME).components().add(cr);
        String id = ApiUtil.getCreatedId(resp);
        resp.close();
        // registered components will be removed automatically
        testContext.getOrCreateCleanup(REALM_NAME).addComponentId(id);
        return id;
    }

    private ComponentRepresentation getComponent(String name, String providerType) {
        return adminClient.realm(REALM_NAME).components().query(null, providerType, name).get(0);
    }

    private void updateComponent(ComponentRepresentation cr) {
        adminClient.realm(REALM_NAME).components().component(cr.getId()).update(cr);
    }

    private void deleteComponent(String id) {
        adminClient.realm(REALM_NAME).components().component(id).remove();
    }

    private String createCondition(String name, String providerId, String subType, Consumer<ComponentRepresentation> op) {
        ComponentRepresentation component = createComponentInstance(name, providerId, ClientPolicyConditionProvider.class.getName(), subType);
        op.accept(component);
        return createComponent(component);
    }

    private void registerCondition(String conditionName, String policyName) {
        ComponentRepresentation policy = getPolicy(policyName);
        List<String> conditionIds = policy.getConfig().get(DefaultClientPolicyProviderFactory.CONDITION_IDS);
        if (conditionIds == null) conditionIds = new ArrayList<String>();
        ComponentRepresentation condition = getCondition(conditionName);
        conditionIds.add(condition.getId());
        policy.getConfig().put(DefaultClientPolicyProviderFactory.CONDITION_IDS, conditionIds);
        updatePolicy(policy);
    }

    private ComponentRepresentation getCondition(String name) {
        return getComponent(name, ClientPolicyConditionProvider.class.getName());
    }

    private void updateCondition(String name, Consumer<ComponentRepresentation> op) {
        ComponentRepresentation condition = getCondition(name);
        op.accept(condition);
        updateComponent(condition);
    }

    private void deleteCondition(String conditionName, String policyName) {
        ComponentRepresentation policy = getPolicy(policyName);
        List<String> conditionIds = policy.getConfig().get(DefaultClientPolicyProviderFactory.CONDITION_IDS);
        ComponentRepresentation condition = getCondition(conditionName);
        String conditionId = condition.getId();
        adminClient.realm(REALM_NAME).components().component(conditionId).remove();
        conditionIds.remove(conditionId);
        policy.getConfig().put(DefaultClientPolicyProviderFactory.CONDITION_IDS, conditionIds);
        updatePolicy(policy);
    }

    private String createExecutor(String name, String providerId, String subType, Consumer<ComponentRepresentation> op) {
        ComponentRepresentation component = createComponentInstance(name, providerId, ClientPolicyExecutorProvider.class.getName(), subType);
        op.accept(component);
        return createComponent(component);
    }

    private void registerExecutor(String executorName, String policyName) {
        ComponentRepresentation policy = getPolicy(policyName);
        List<String> executorIds = policy.getConfig().get(DefaultClientPolicyProviderFactory.EXECUTOR_IDS);
        if (executorIds == null) executorIds = new ArrayList<>();
        ComponentRepresentation executor = getExecutor(executorName);
        executorIds.add(executor.getId());
        policy.getConfig().put(DefaultClientPolicyProviderFactory.EXECUTOR_IDS, executorIds);
        updatePolicy(policy);
    }

    private ComponentRepresentation getExecutor(String name) {
        return getComponent(name, ClientPolicyExecutorProvider.class.getName());
    }

    private void updateExecutor(String name, Consumer<ComponentRepresentation> op) {
        ComponentRepresentation executor = getExecutor(name);
        op.accept(executor);
        updateComponent(executor);
    }

    private void deleteExecutor(String executorName, String policyName) {
        ComponentRepresentation policy = getPolicy(policyName);
        List<String> executorIds = policy.getConfig().get(DefaultClientPolicyProviderFactory.EXECUTOR_IDS);
        ComponentRepresentation executor = getExecutor(executorName);
        String executorId = executor.getId();
        adminClient.realm(REALM_NAME).components().component(executorId).remove();
        executorIds.remove(executorId);
        policy.getConfig().put(DefaultClientPolicyProviderFactory.EXECUTOR_IDS, executorIds);
        updatePolicy(policy);
    }

    private String createPolicy(String name, String providerId, String subType, List<String> conditions, List<String> executors) {
        ComponentRepresentation component = createComponentInstance(name, providerId, ClientPolicyProvider.class.getName(), subType);
        component.getConfig().put(DefaultClientPolicyProviderFactory.CONDITION_IDS, conditions);
        component.getConfig().put(DefaultClientPolicyProviderFactory.EXECUTOR_IDS, executors);
        return createComponent(component);
    }

    private ComponentRepresentation getPolicy(String name) {
        return getComponent(name, ClientPolicyProvider.class.getName());
    }

    private void updatePolicy(ComponentRepresentation policy) {
        updateComponent(policy);
    }

    private void deletePolicy(String policyName) {
        ComponentRepresentation policy = getPolicy(policyName);
        List<String> conditionIds = policy.getConfig().get(DefaultClientPolicyProviderFactory.CONDITION_IDS);
        List<String> executorIds = policy.getConfig().get(DefaultClientPolicyProviderFactory.EXECUTOR_IDS);
        conditionIds.stream().forEach(i->adminClient.realm(REALM_NAME).components().component(i).remove());
        executorIds.stream().forEach(i->adminClient.realm(REALM_NAME).components().component(i).remove());
        adminClient.realm(REALM_NAME).components().component(policy.getId()).remove();
    }

    private String createClientByAdmin(String clientName, Consumer<ClientRepresentation> op) throws ClientPolicyException {
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(clientName);
        clientRep.setName(clientName);
        clientRep.setProtocol("openid-connect");
        clientRep.setBearerOnly(Boolean.FALSE);
        clientRep.setPublicClient(Boolean.FALSE);
        clientRep.setServiceAccountsEnabled(Boolean.TRUE);
        clientRep.setRedirectUris(Collections.singletonList("https://localhost:8543/auth/realms/master/app/auth"));
        op.accept(clientRep);
        Response resp = adminClient.realm(REALM_NAME).clients().create(clientRep);
        if (resp.getStatus() == Response.Status.BAD_REQUEST.getStatusCode()) {
            throw new ClientPolicyException(Errors.INVALID_REGISTRATION, "registration error by admin");
        }
        resp.close();
        assertEquals(Response.Status.CREATED.getStatusCode(), resp.getStatus());
        return ApiUtil.getCreatedId(resp);
    }

    private ClientRepresentation getClientByAdmin(String clientId) {
        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(clientId);
        return clientResource.toRepresentation();
    }

    private void updateClientByAdmin(String clientId, Consumer<ClientRepresentation> op) {
        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(clientId);
        ClientRepresentation clientRep = clientResource.toRepresentation();
        op.accept(clientRep);
        clientResource.update(clientRep);
    }

    private void deleteClientByAdmin(String clientId) {
        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(clientId);
        clientResource.remove();
    }

    private String createClientDynamically(String clientName, Consumer<OIDCClientRepresentation> op) throws ClientRegistrationException {
        OIDCClientRepresentation clientRep = new OIDCClientRepresentation();
        clientRep.setClientName(clientName);
        clientRep.setClientUri("https://localhost:8543");
        clientRep.setRedirectUris(Collections.singletonList("https://localhost:8543/auth/realms/master/app/auth"));
        op.accept(clientRep);
        OIDCClientRepresentation response = reg.oidc().create(clientRep);
        reg.auth(Auth.token(response));
        return response.getClientId();
    }

    private OIDCClientRepresentation getClientDynamically(String clientId) throws ClientRegistrationException {
        return reg.oidc().get(clientId);
    }

    private void updateClientDynamically(String clientId, Consumer<OIDCClientRepresentation> op) throws ClientRegistrationException {
        OIDCClientRepresentation clientRep = reg.oidc().get(clientId);
        op.accept(clientRep);
        OIDCClientRepresentation response = reg.oidc().update(clientRep);
        reg.auth(Auth.token(response));
    }

    private void deleteClientDynamically(String clientId) throws ClientRegistrationException {
        reg.oidc().delete(clientId);
    }

    private void setConditionRegistrationMethods(ComponentRepresentation provider, List<String> registrationMethods) {
        provider.getConfig().put(UpdatingClientSourceConditionFactory.UPDATE_CLIENT_SOURCE, registrationMethods);
    }

    private void setConditionClientRoles(ComponentRepresentation provider, List<String> clientRoles) {
        provider.getConfig().put(ClientRolesConditionFactory.ROLES, clientRoles);
    }

    private void setConditionClientIpAddress(ComponentRepresentation provider, List<String> clientIpAddresses) {
        provider.getConfig().put(ClientIpAddressConditionFactory.IPADDR, clientIpAddresses);
    }

    private void setConditionClientScopes(ComponentRepresentation provider, List<String> clientScopes) {
        provider.getConfig().put(ClientScopesConditionFactory.SCOPES, clientScopes);
    }

    private void setConditionClientAccessType(ComponentRepresentation provider, List<String> clientAccessTypes) {
        provider.getConfig().put(ClientAccessTypeConditionFactory.TYPE, clientAccessTypes);
    }

    private void setConditionUpdatingClientSourceHosts(ComponentRepresentation provider, List<String> hosts) {
        provider.getConfig().put(UpdatingClientSourceHostsConditionFactory.HOSTS, hosts);
    }

    private void setConditionUpdatingClientSourceGroups(ComponentRepresentation provider, List<String> groups) {
        provider.getConfig().put(UpdatingClientSourceGroupsConditionFactory.GROUPS, groups);
    }

    private void setConditionUpdatingClientSourceRoles(ComponentRepresentation provider, List<String> groups) {
        provider.getConfig().put(UpdatingClientSourceRolesConditionFactory.ROLES, groups);
    }

    private void setExecutorAugmentActivate(ComponentRepresentation provider) {
        provider.getConfig().putSingle("is-augment", Boolean.TRUE.toString());
    }

    private void setExecutorAugmentDeactivate(ComponentRepresentation provider) {
        provider.getConfig().putSingle("is-augment", Boolean.FALSE.toString());
    }

    private void setExecutorAcceptedClientAuthMethods(ComponentRepresentation provider, List<String> acceptedClientAuthMethods) {
        provider.getConfig().put(SecureClientAuthEnforceExecutorFactory.CLIENT_AUTHNS, acceptedClientAuthMethods);
    }

    private void setExecutorAugmentedClientAuthMethod(ComponentRepresentation provider, String augmentedClientAuthMethod) {
        provider.getConfig().putSingle(SecureClientAuthEnforceExecutorFactory.CLIENT_AUTHNS_AUGMENT, augmentedClientAuthMethod);
    }

    void authCreateClients() {
        reg.auth(Auth.token(getToken("create-clients", "password")));
    }

    void authManageClients() {
        reg.auth(Auth.token(getToken("manage-clients", "password")));
    }

    void authNoAccess() {
        reg.auth(Auth.token(getToken("no-access", "password")));
    }

    private String getToken(String username, String password) {
        try {
            return oauth.doGrantAccessTokenRequest(REALM_NAME, username, password, null, Constants.ADMIN_CLI_CLIENT_ID, null).getAccessToken();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
