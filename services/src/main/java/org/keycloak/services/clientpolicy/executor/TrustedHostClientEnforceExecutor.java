package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperUtils;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class TrustedHostClientEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(TrustedHostClientEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public TrustedHostClientEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
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
        switch (context.getEvent()) {
            case REGISTER:
            case UPDATE:
                ClientUpdateContext registerClientContext = (ClientUpdateContext) context;

                verifyHost();
                verifyClientUrls(registerClientContext.getProposedClientRepresentation());
                break;
            case VIEW:
            case UNREGISTER:
                verifyHost();
                break;
            default:
                return;
        }
    }

    private void verifyHost() throws ClientPolicyException {
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
        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Host not trusted.");
    }

    private List<String> getTrustedHosts() {
        List<String> trustedHostsConfig = componentModel.getConfig().getList(TrustedHostClientEnforceExecutorFactory.TRUSTED_HOSTS);
        return trustedHostsConfig.stream().filter((String hostname) -> !hostname.startsWith("*.")).collect(Collectors.toList());
    }

    protected List<String> getTrustedDomains() {
        List<String> trustedHostsConfig = componentModel.getConfig().getList(TrustedHostClientEnforceExecutorFactory.TRUSTED_HOSTS);
        List<String> domains = new LinkedList<>();

        for (String hostname : trustedHostsConfig) {
            if (hostname.startsWith("*.")) {
                hostname = hostname.substring(2);
                domains.add(hostname);
            }
        }

        return domains;
    }

    private String verifyHostInTrustedHosts(String hostAddress, List<String> trustedHosts) {
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


    private String verifyHostInTrustedDomains(String hostAddress, List<String> trustedDomains) {
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

    private void verifyClientUrls(ClientRepresentation client) throws ClientPolicyException {
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

    private void checkURLTrusted(String url, List<String> trustedHosts, List<String> trustedDomains) throws ClientPolicyException {
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
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "URL is malformed");
        }

        ServicesLogger.LOGGER.urlDoesntMatch(url);
        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "URL doesn't match any trusted host or trusted domain");
    }

    private String relativeToAbsoluteURI(String rootUrl, String relative) {
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
        return parseBoolean(TrustedHostClientEnforceExecutorFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH);
    }

    boolean isClientUrisMustMatch() {
        return parseBoolean(TrustedHostClientEnforceExecutorFactory.CLIENT_URIS_MUST_MATCH);
    }

    // True by default
    private boolean parseBoolean(String propertyKey) {
        String val = componentModel.getConfig().getFirst(propertyKey);
        return val == null || Boolean.parseBoolean(val);
    }
}
