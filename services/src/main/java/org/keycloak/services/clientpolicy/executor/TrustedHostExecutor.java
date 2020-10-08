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

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperUtils;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class TrustedHostExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(MaxClientsExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public TrustedHostExecutor(KeycloakSession session, ComponentModel componentModel) {
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
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        ClientUpdateContext clientUpdateContext = null;
        switch (context.getEvent()) {
            case REGISTER:
                clientUpdateContext = (ClientUpdateContext)context;
                beforeRegister(clientUpdateContext.getProposedClientRepresentation());
            break;
            case VIEW:
                beforeView();
                break;
            case UNREGISTER:
                beforeDelete();
                break;
            default:
                return;
        }
    }

    private void beforeRegister(ClientRepresentation proposedClient) throws ClientPolicyException {
        verifyHost();
        verifyClientUrls(proposedClient);
    }

    private void beforeView() throws ClientPolicyException {
        verifyHost();
    }

    private void beforeDelete() throws ClientPolicyException {
        verifyHost();
    }

    // IMPL

    protected void verifyHost() throws ClientPolicyException {
        boolean hostMustMatch = isHostMustMatch();
        if (!hostMustMatch) {
            return;
        }

        String hostAddress = session.getContext().getConnection().getRemoteAddr();

        logger.debugf("Verifying remote host : %s", hostAddress);

        List<String> trustedHosts = getTrustedHosts();
        List<String> trustedDomains = getTrustedDomains();

        // Verify trustedHosts by their IP addresses
        String verifiedHost = verifyHostInTrustedHosts(hostAddress, trustedHosts);
        if (verifiedHost != null) {
            return;
        }

        // Verify domains if hostAddress hostname belongs to the domain. This assumes proper DNS setup
        verifiedHost = verifyHostInTrustedDomains(hostAddress, trustedDomains);
        if (verifiedHost != null) {
            return;
        }

        ServicesLogger.LOGGER.failedToVerifyRemoteHost(hostAddress);
        throw new ClientPolicyException(Errors.INVALID_REGISTRATION, "Host not trusted.");
    }


    protected List<String> getTrustedHosts() {
        List<String> trustedHostsConfig = componentModel.getConfig().getList(TrustedHostExecutorFactory.TRUSTED_HOSTS);
        return trustedHostsConfig.stream().filter((String hostname) -> {

            return !hostname.startsWith("*.");

        }).collect(Collectors.toList());
    }


    protected List<String> getTrustedDomains() {
        List<String> trustedHostsConfig = componentModel.getConfig().getList(TrustedHostExecutorFactory.TRUSTED_HOSTS);
        List<String> domains = new LinkedList<>();

        for (String hostname : trustedHostsConfig) {
            if (hostname.startsWith("*.")) {
                hostname = hostname.substring(2);
                domains.add(hostname);
            }
        }

        return domains;
    }

    protected String verifyHostInTrustedHosts(String hostAddress, List<String> trustedHosts) {
        for (String confHostName : trustedHosts) {
            try {
                String hostIPAddress = InetAddress.getByName(confHostName).getHostAddress();

                logger.tracef("Trying host '%s' of address '%s'", confHostName, hostIPAddress);
                if (hostIPAddress.equals(hostAddress)) {
                    logger.debugf("Successfully verified host : %s", confHostName);
                    return confHostName;
                }
            } catch (UnknownHostException uhe) {
                logger.debugf(uhe, "Unknown host from realm configuration: %s", confHostName);
            }
        }

        return null;
    }

    protected String verifyHostInTrustedDomains(String hostAddress, List<String> trustedDomains) {
        if (!trustedDomains.isEmpty()) {
            try {
                String hostname = InetAddress.getByName(hostAddress).getHostName();

                logger.debugf("Trying verify request from address '%s' of host '%s' by domains", hostAddress, hostname);

                for (String confDomain : trustedDomains) {
                    if (hostname.endsWith(confDomain)) {
                        logger.debugf("Successfully verified host '%s' by trusted domain '%s'", hostname, confDomain);
                        return hostname;
                    }
                }
            } catch (UnknownHostException uhe) {
                logger.debugf(uhe, "Request of address '%s' came from unknown host. Skip verification by domains", hostAddress);
            }
        }

        return null;
    }

    protected void verifyClientUrls(ClientRepresentation client) throws ClientPolicyException {
        boolean redirectUriMustMatch = isClientUrisMustMatch();
        if (!redirectUriMustMatch) {
            return;
        }

        List<String> trustedHosts = getTrustedHosts();
        List<String> trustedDomains = getTrustedDomains();

        String rootUrl = client.getRootUrl();
        String baseUrl = client.getBaseUrl();
        String adminUrl = client.getAdminUrl();
        List<String> redirectUris = client.getRedirectUris();

        baseUrl = relativeToAbsoluteURI(rootUrl, baseUrl);
        adminUrl = relativeToAbsoluteURI(rootUrl, adminUrl);
        Set<String> resolvedRedirects = PairwiseSubMapperUtils.resolveValidRedirectUris(rootUrl, redirectUris);

        if (rootUrl != null) {
            checkURLTrusted(rootUrl, trustedHosts, trustedDomains);
        }

        if (baseUrl != null) {
            checkURLTrusted(baseUrl, trustedHosts, trustedDomains);
        }
        if (adminUrl != null) {
            checkURLTrusted(adminUrl, trustedHosts, trustedDomains);
        }
        for (String redirect : resolvedRedirects) {
            checkURLTrusted(redirect, trustedHosts, trustedDomains);
        }

    }

    protected void checkURLTrusted(String url, List<String> trustedHosts, List<String> trustedDomains) throws ClientPolicyException {
        try {
            String host = new URL(url).getHost();

            for (String trustedHost : trustedHosts) {
                if (host.equals(trustedHost)) {
                    return;
                }
            }

            for (String trustedDomain : trustedDomains) {
                if (host.endsWith(trustedDomain)) {
                    return;
                }
            }
        } catch (MalformedURLException mfe) {
            logger.debugf(mfe, "URL '%s' is malformed", url);
            throw new ClientPolicyException(Errors.INVALID_REGISTRATION, "URL is malformed");
        }

        ServicesLogger.LOGGER.urlDoesntMatch(url);
        throw new ClientPolicyException(Errors.INVALID_REGISTRATION, "URL doesn't match any trusted host or trusted domain");
    }

    private static String relativeToAbsoluteURI(String rootUrl, String relative) {
        if (relative == null) {
            return null;
        }

        if (!relative.startsWith("/")) {
            return relative;
        } else if (rootUrl == null || rootUrl.isEmpty()) {
            return null;
        }

        return rootUrl + relative;
    }

    boolean isHostMustMatch() {
        return parseBoolean(TrustedHostExecutorFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH);
    }

    boolean isClientUrisMustMatch() {
        return parseBoolean(TrustedHostExecutorFactory.CLIENT_URIS_MUST_MATCH);
    }

    // True by default
    private boolean parseBoolean(String propertyKey) {
        String val = componentModel.getConfig().getFirst(propertyKey);
        return val==null || Boolean.parseBoolean(val);
    }
}
