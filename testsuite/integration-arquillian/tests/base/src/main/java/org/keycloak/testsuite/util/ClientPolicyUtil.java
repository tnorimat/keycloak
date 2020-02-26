package org.keycloak.testsuite.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.authentication.authenticators.client.JWTClientSecretAuthenticator;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyProvider;
import org.keycloak.services.clientpolicy.DefaultClientPolicies;
import org.keycloak.services.clientpolicy.condition.ClientPolicyCondition;
import org.keycloak.services.clientpolicy.condition.impl.ClientAccessTypeConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.ClientRedirectUrisConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.ClientRolesConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.ClientScopesConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.GroupsConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.HostsConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.ClientIpAddressConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.UserRolesConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.UsersConditionFactory;
import org.keycloak.services.clientpolicy.condition.impl.AuthnMethodsConditionFactory;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutor;
import org.keycloak.services.clientpolicy.executor.impl.ClientAuthenticationExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.HoKTokenEnforceExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.PKCEEnforceExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureClientAuthenticationExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureRedirectUriExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureRequestObjectExecutor;
import org.keycloak.services.clientpolicy.executor.impl.SecureRequestObjectExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureResponseTypeExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureSessionsExecutorFactory;
import org.keycloak.services.clientpolicy.executor.impl.SecureSigningAlgorithmExecutorFactory;
import org.keycloak.services.clientpolicy.impl.DefaultClientPolicyProviderFactory;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.TestContext;

public class ClientPolicyUtil {

    private static final String BUILTIN_ADMIN_PREFIX = "builtin-admin-";
    private static final String BUILTIN_ADMIN_SUFFIX = "-admin-reg";
    private static final String BUILTIN_ANON_PREFIX = "builtin-anon-";
    private static final String BUILTIN_ANON_SUFFIX = "-anonymous-reg";
    private static final String BUILTIN_AUTH_PREFIX = "builtin-auth-";
    private static final String BUILTIN_AUTH_SUFFIX = "-anonymous-reg";
    private static final String BUILTIN_FAPIRO_PREFIX = "builtin-fapiro-";
    private static final String BUILTIN_FAPIRO_SUFFIX = "-fapiro";
    private static final String BUILTIN_FAPIRW_PREFIX = "builtin-fapirw-";
    private static final String BUILTIN_FAPIRW_SUFFIX = "-fapirw";

    public static void addAdminRestApiPolicy(Logger logger, String realmName, Keycloak adminClient, TestContext testContext) {
        List<String> conditions = new ArrayList<String>();
        List<String> executors = new ArrayList<String>();

        logger.info("Registering Policy for Anonymous Dynamic Client Registration");

        // create conditions
        List<String> authnMethods = new ArrayList<>();
        authnMethods.add(AuthnMethodsConditionFactory.BY_ADMIN_REST_API);
        addAuthCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + AuthnMethodsConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, authnMethods);

        List<String> ipAddrs = new ArrayList<>();
        ipAddrs.add("0.0.0.0");
        ipAddrs.add("127.0.0.1");
        addClientIpAddressCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + ClientIpAddressConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, ipAddrs);

        List<String> hosts = new ArrayList<>();
        hosts.add("example.com");
        hosts.add("localhost:8543");
        addHostsCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + HostsConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, hosts);

        List<String> users = new ArrayList<>();
        users.add("mystaff");
        users.add("admin");
        addUsersCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + UsersConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, users);

        /*
        List<String> groups = new ArrayList<>();
        groups.add("topGroup");
        addRegistererGroupsCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + RegistererGroupsConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, groups);
        */

        List<String> userRoles = new ArrayList<>();
        userRoles.add("manage-account");
        userRoles.add("admin");
        addUserRolesCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + UserRolesConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, userRoles);

        /*
        List<String> clientRoles = new ArrayList<>();
        clientRoles.add("view-profile");
        addRegistererClientRolesCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + RegistererUserRolesConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientRoles);
        */

        List<String> clientScopes = new ArrayList<>();
        clientScopes.add("offline_access");
        clientScopes.add("microprofile-jwt");
        addClientScopesCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + ClientScopesConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, ClientScopesConditionFactory.OPTIONAL, clientScopes);

        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://localhost:8543");
        addClientRedirectUrisCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + ClientRedirectUrisConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, redirectUris);

        // create executors
        addPKCEEnforceExecutor(logger, executors, BUILTIN_ADMIN_PREFIX + PKCEEnforceExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        List<String> clientAuthns = new ArrayList<String>();
        clientAuthns.add(ClientIdAndSecretAuthenticator.PROVIDER_ID);
        clientAuthns.add(JWTClientAuthenticator.PROVIDER_ID);
        clientAuthns.add(JWTClientSecretAuthenticator.PROVIDER_ID);
        clientAuthns.add(X509ClientAuthenticator.PROVIDER_ID);
        addClientAuthenticationExecutor(logger, executors, BUILTIN_ADMIN_PREFIX + ClientAuthenticationExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientAuthns);

        // create policy
        addDefaultClientPolicy(logger, conditions, executors, DefaultClientPolicies.BUILTIN_POLICY_NAME + BUILTIN_ADMIN_SUFFIX, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);
    }

    public static void addAnonymousPolicy(Logger logger, String realmName, Keycloak adminClient, TestContext testContext) {
        List<String> conditions = new ArrayList<String>();
        List<String> executors = new ArrayList<String>();

        logger.info("Registering Policy for Anonymous Dynamic Client Registration");

        // create conditions
        List<String> authnMethods = new ArrayList<>();
        authnMethods.add(RegistrationAuth.ANONYMOUS.name());
        addAuthCondition(logger, conditions, BUILTIN_ANON_PREFIX + AuthnMethodsConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, authnMethods);

        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://localhost:8543");
        addClientRedirectUrisCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + ClientRedirectUrisConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, redirectUris);

        // create executors
        addPKCEEnforceExecutor(logger, executors, BUILTIN_ANON_PREFIX + PKCEEnforceExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        List<String> clientAuthns = new ArrayList<String>();
        clientAuthns.add(ClientIdAndSecretAuthenticator.PROVIDER_ID);
        clientAuthns.add(JWTClientAuthenticator.PROVIDER_ID);
        clientAuthns.add(JWTClientSecretAuthenticator.PROVIDER_ID);
        clientAuthns.add(X509ClientAuthenticator.PROVIDER_ID);
        addClientAuthenticationExecutor(logger, executors, BUILTIN_ANON_PREFIX + ClientAuthenticationExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientAuthns);

        // create policy
        addDefaultClientPolicy(logger, conditions, executors, DefaultClientPolicies.BUILTIN_POLICY_NAME + BUILTIN_ANON_SUFFIX, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);
    }

    public static void addAuthPolicy(Logger logger, String realmName, Keycloak adminClient, TestContext testContext) {
        List<String> conditions = new ArrayList<String>();
        List<String> executors = new ArrayList<String>();

        logger.info("Registering Policy for Authenticated Dynamic Client Registration");

        // create conditions
        List<String> authnMethods = new ArrayList<>();
        authnMethods.add(RegistrationAuth.AUTHENTICATED.name());
        addAuthCondition(logger, conditions, BUILTIN_AUTH_PREFIX + AuthnMethodsConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, authnMethods);

        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://localhost:8543");
        addClientRedirectUrisCondition(logger, conditions, BUILTIN_ADMIN_PREFIX + ClientRedirectUrisConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, redirectUris);

        // create executors
        addPKCEEnforceExecutor(logger, executors, BUILTIN_AUTH_PREFIX + PKCEEnforceExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addSecureRedirectUriExecutor(logger, executors, BUILTIN_AUTH_PREFIX + SecureRedirectUriExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        List<String> clientAuthns = new ArrayList<String>();
        clientAuthns.add(JWTClientAuthenticator.PROVIDER_ID);
        clientAuthns.add(JWTClientSecretAuthenticator.PROVIDER_ID);
        clientAuthns.add(X509ClientAuthenticator.PROVIDER_ID);
        addClientAuthenticationExecutor(logger, executors, BUILTIN_AUTH_PREFIX + ClientAuthenticationExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientAuthns);

        addHoKTokenEnforceExecutor(logger, executors, BUILTIN_AUTH_PREFIX + HoKTokenEnforceExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addSecureSigningAlgorithmExecutor(logger, executors, BUILTIN_AUTH_PREFIX + SecureSigningAlgorithmExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        // create policy
        addDefaultClientPolicy(logger, conditions, executors, DefaultClientPolicies.BUILTIN_POLICY_NAME + BUILTIN_AUTH_SUFFIX, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);
    }

    public static void addFAPIROPolicy(Logger logger, String realmName, Keycloak adminClient, TestContext testContext, String clientId) {
        List<String> conditions = new ArrayList<String>();
        List<String> executors = new ArrayList<String>();

        logger.info("Registering Policy for Financial-grade API Read Only Security Profile");

        // create conditions
        List<String> authnMethods = new ArrayList<>();
        authnMethods.add(RegistrationAuth.ANONYMOUS.name());
        authnMethods.add(RegistrationAuth.AUTHENTICATED.name());
        addAuthCondition(logger, conditions, BUILTIN_FAPIRO_PREFIX + AuthnMethodsConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, authnMethods);

        List<String> clientTypes = new ArrayList<>();
        clientTypes.add(ClientAccessTypeConditionFactory.TYPE_CONFIDENTIAL);
        addClientAccessTypeCondition(logger, conditions, BUILTIN_FAPIRO_PREFIX + ClientAccessTypeConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientTypes);

        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://localhost:8543");
        redirectUris.add("https://localhost:8543/auth/realms/master/app/auth");
        addClientRedirectUrisCondition(logger, conditions, BUILTIN_FAPIRO_PREFIX + ClientRedirectUrisConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, redirectUris);

        // create executors
        addPKCEEnforceExecutor(logger, executors, BUILTIN_FAPIRO_PREFIX + PKCEEnforceExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addSecureRedirectUriExecutor(logger, executors, BUILTIN_FAPIRO_PREFIX + SecureRedirectUriExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addSecureSessionsExecutor(logger, executors, BUILTIN_FAPIRO_PREFIX + SecureSessionsExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        List<String> clientAuthns = new ArrayList<String>();
        clientAuthns.add(ClientIdAndSecretAuthenticator.PROVIDER_ID);
        clientAuthns.add(JWTClientAuthenticator.PROVIDER_ID);
        clientAuthns.add(JWTClientSecretAuthenticator.PROVIDER_ID);
        clientAuthns.add(X509ClientAuthenticator.PROVIDER_ID);
        addClientAuthenticationExecutor(logger, executors, BUILTIN_FAPIRO_PREFIX + ClientAuthenticationExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientAuthns);

        // create policy
        addDefaultClientPolicy(logger, conditions, executors, DefaultClientPolicies.BUILTIN_POLICY_NAME + BUILTIN_FAPIRO_SUFFIX, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);
    }

    public static void addFAPIRWPolicy(Logger logger, String realmName, Keycloak adminClient, TestContext testContext, String clientId) {
        List<String> conditions = new ArrayList<String>();
        List<String> executors = new ArrayList<String>();

        logger.info("Registering Policy for Financial-grade API Read and Write Security Profile");

        // create conditions
        List<String> authnMethods = new ArrayList<>();
        authnMethods.add(RegistrationAuth.ANONYMOUS.name());
        authnMethods.add(RegistrationAuth.AUTHENTICATED.name());
        addAuthCondition(logger, conditions, BUILTIN_FAPIRW_PREFIX + AuthnMethodsConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, authnMethods);

        List<String> clientTypes = new ArrayList<>();
        clientTypes.add(ClientAccessTypeConditionFactory.TYPE_CONFIDENTIAL);
        addClientAccessTypeCondition(logger, conditions, BUILTIN_FAPIRW_PREFIX + ClientAccessTypeConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientTypes);

        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("https://localhost:8543");
        redirectUris.add("https://localhost:8543/auth/realms/master/app/auth");
        addClientRedirectUrisCondition(logger, conditions, BUILTIN_FAPIRW_PREFIX + ClientRedirectUrisConditionFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, redirectUris);

        // create executors
        addPKCEEnforceExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + PKCEEnforceExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addSecureRedirectUriExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + SecureRedirectUriExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addSecureSessionsExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + SecureSessionsExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        //addSecureResponseTypeExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + SecureResponseTypeExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        //addSecureRequestObjectExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + SecureRequestObjectExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        //addSecureClientAuthenticationExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + SecureClientAuthenticationExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addHoKTokenEnforceExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + HoKTokenEnforceExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        addSecureSigningAlgorithmExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + SecureSigningAlgorithmExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);

        List<String> clientAuthns = new ArrayList<String>();
        clientAuthns.add(JWTClientAuthenticator.PROVIDER_ID);
        clientAuthns.add(X509ClientAuthenticator.PROVIDER_ID);
        addClientAuthenticationExecutor(logger, executors, BUILTIN_FAPIRW_PREFIX + ClientAuthenticationExecutorFactory.PROVIDER_ID, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE, clientAuthns);

        // create policy
        addDefaultClientPolicy(logger, conditions, executors, DefaultClientPolicies.BUILTIN_POLICY_NAME + BUILTIN_FAPIRW_SUFFIX, realmName, adminClient, testContext, DefaultClientPolicies.BUILTIN_TYPE);
    }

    private static String addDefaultClientPolicy(Logger logger, List<String> conditions, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering DefaultClientPolicy");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, DefaultClientPolicyProviderFactory.PROVIDER_ID, ClientPolicyProvider.class.getName(), policyType);
        provider.getConfig().put(DefaultClientPolicies.CONDITIONS, conditions);
        provider.getConfig().put(DefaultClientPolicies.EXECUTORS, executors);
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addSecureSigningAlgorithmExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering SecureSigningAlgorithmExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, SecureSigningAlgorithmExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addHoKTokenEnforceExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering HoKTokenEnforceExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, HoKTokenEnforceExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addSecureClientAuthenticationExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering SecureClientAuthenticationExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, SecureClientAuthenticationExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addSecureRequestObjectExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering SecureRequestObjectExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, SecureRequestObjectExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addSecureResponseTypeExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering SecureResponseTypeExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, SecureResponseTypeExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addPKCEEnforceExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering PKCEEnforceExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, PKCEEnforceExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addSecureRedirectUriExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering SecureRedirectUriExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, SecureRedirectUriExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addSecureSessionsExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType) {
        logger.info("... Registering SecureSessionsExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, SecureSessionsExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addClientAuthenticationExecutor(Logger logger, List<String> executors, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> clientAuthns) {
        logger.info("... Registering ClientAuthenticationExecutor");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, ClientAuthenticationExecutorFactory.PROVIDER_ID, ClientPolicyExecutor.class.getName(), policyType);
        provider.getConfig().put(ClientAuthenticationExecutorFactory.CLIENT_AUTHNS, clientAuthns);
        executors.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addClientRedirectUrisCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> redirectUris) {
        logger.info("... Registering ClientRedirectUrisCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, ClientRedirectUrisConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(ClientRedirectUrisConditionFactory.URIS, redirectUris);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addClientScopesCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, String scopeType, List<String> clientScopes) {
        logger.info("... Registering ClientScopesCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, ClientScopesConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().putSingle(ClientScopesConditionFactory.TYPE, scopeType);
        provider.getConfig().put(ClientScopesConditionFactory.SCOPES, clientScopes);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addClientRolesCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> userRoles) {
        logger.info("... Registering ClientRolesCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, ClientRolesConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(ClientRolesConditionFactory.ROLES, userRoles);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addUserRolesCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> userRoles) {
        logger.info("... Registering UserRolesCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, UserRolesConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(UserRolesConditionFactory.ROLES, userRoles);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addGroupsCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> groups) {
        logger.info("... Registering GroupsCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, GroupsConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(GroupsConditionFactory.GROUPS, groups);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addUsersCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> hosts) {
        logger.info("... Registering UsersCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, UsersConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(UsersConditionFactory.USERS, hosts);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addHostsCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> hosts) {
        logger.info("... Registering HostsCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, HostsConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(HostsConditionFactory.HOSTS, hosts);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addClientIpAddressCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> ipAddrs) {
        logger.info("... Registering ClientIpAddressCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, ClientIpAddressConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(ClientIpAddressConditionFactory.IPADDR, ipAddrs);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addAuthCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> authnMethods) {
        logger.info("... Registering AuthCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, AuthnMethodsConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(AuthnMethodsConditionFactory.AUTH_METHOD, authnMethods);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addClientAccessTypeCondition(Logger logger, List<String> conditions, String providerName, String realmName, Keycloak adminClient, TestContext testContext, String policyType, List<String> accessTypes) {
        logger.info("... Registering ClientAccessTypeCondition");
        ComponentRepresentation provider = createProviderInstance(providerName, realmName, ClientAccessTypeConditionFactory.PROVIDER_ID, ClientPolicyCondition.class.getName(), policyType);
        provider.getConfig().put(ClientAccessTypeConditionFactory.TYPE, accessTypes);
        conditions.add(provider.getId());
        return addComponent(provider, realmName, adminClient, testContext);
    }

    private static String addComponent(ComponentRepresentation component, String realmName, Keycloak adminClient, TestContext testContext) {
        Response resp = adminClient.realm(realmName).components().add(component);
        resp.close();
        String id = ApiUtil.getCreatedId(resp);
        // registered components will be removed automatically
        testContext.getOrCreateCleanup(realmName).addComponentId(id);
        return id;
    }

    private static ComponentRepresentation createProviderInstance(String name, String realmId, String providerId, String providerType, String policyType) {
        ComponentRepresentation rep = new ComponentRepresentation();
        rep.setId(org.keycloak.models.utils.KeycloakModelUtils.generateId());
        rep.setName(name);
        rep.setParentId(realmId);
        rep.setProviderId(providerId);
        rep.setProviderType(providerType);
        rep.setSubType(policyType);
        rep.setConfig(new MultivaluedHashMap<>());
        return rep;
    }

    public static String createOidcBearerOnlyClientByAdminRestApi(String name, String realmName, Keycloak adminClient) {
        ClientRepresentation clientRep = createOidcClientRep(name);
        clientRep.setBearerOnly(Boolean.TRUE);
        clientRep.setPublicClient(Boolean.FALSE);
        return createClientByAdminRestApi(clientRep, realmName, adminClient);
    }

    public static String createOidcConfidentialClientByAdminRestApi(String name, String realmName, Keycloak adminClient) {
        ClientRepresentation clientRep = createOidcClientRep(name);
        clientRep.setBearerOnly(Boolean.FALSE);
        clientRep.setPublicClient(Boolean.FALSE);
        clientRep.setServiceAccountsEnabled(Boolean.TRUE);
        clientRep.setRedirectUris(Collections.singletonList("https://localhost:8543"));
        String id = createClientByAdminRestApi(clientRep, realmName, adminClient);
        return id;
    }

    public static ClientRepresentation createOidcClientRep(String name) {
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(name);
        clientRep.setName(name);
        clientRep.setProtocol("openid-connect");
        return clientRep;
    }

    public static String createClientByAdminRestApi(ClientRepresentation clientRep, String realmName, Keycloak adminClient) {
        Response resp = adminClient.realm(realmName).clients().create(clientRep);
        resp.close();
        return ApiUtil.getCreatedId(resp);
    }

    public interface ClientUpdateByAdminRestApiOperation {
        ClientRepresentation run(ClientRepresentation clientRep);
    }

    public static void updateClientByAdminRestApi(String clientId, String realmName, Keycloak adminClient, ClientUpdateByAdminRestApiOperation op) {
        ClientResource clientResource = ApiUtil.findClientByClientId(adminClient.realm(realmName), clientId);
        ClientRepresentation clientRep = clientResource.toRepresentation();
        clientRep = op.run(clientRep);
        clientResource.update(clientRep);
    }

    public static void removeClientByAdminRestApi(String clientDbId, String realmName, Keycloak adminClient) {
        adminClient.realm(realmName).clients().get(clientDbId).remove();
    }

    public static ClientRepresentation findClientRepresentation(String name, String realmName, Keycloak adminClient) {
        ClientResource clientRsc = findClientResource(name, realmName, adminClient);
        if (clientRsc == null) return null;
        return findClientResource(name, realmName, adminClient).toRepresentation();
    }

    public static ClientResource findClientResource(String name, String realmName, Keycloak adminClient) {
        return ApiUtil.findClientResourceByName(adminClient.realm(realmName), name);
    }

    public static ClientResource findClientResourceById(String id, String realmName, Keycloak adminClient) {
        return ApiUtil.findClientResourceByClientId(adminClient.realm(realmName), id);
    }
}
