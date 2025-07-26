package org.keycloak.services.clientpolicy.executor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.AuthorizationRequestContext;
import org.keycloak.services.clientpolicy.context.TokenRequestContext;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jboss.logging.Logger;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class ResourceAudienceBindExecutor implements ClientPolicyExecutorProvider<ResourceAudienceBindExecutor.Configuration> {

    protected final KeycloakSession session;
    protected ResourceAudienceBindExecutor.Configuration configuration;

    private static final Logger logger = Logger.getLogger(ResourceAudienceBindExecutor.class);

    public ResourceAudienceBindExecutor.Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void setupConfiguration(ResourceAudienceBindExecutor.Configuration config) {
        this.configuration = config;
    }

    @Override
    public Class<ResourceAudienceBindExecutor.Configuration> getExecutorConfigurationClass() {
        return ResourceAudienceBindExecutor.Configuration.class;
    }

    public static class Configuration extends ClientPolicyExecutorConfigurationRepresentation {
        @JsonProperty(ResourceAudienceBindExecutorFactory.PERMITTED_RESOURCES)
        protected List<String> allowPermittedResources = null;

        public Configuration() {
        }

        public List<String> getAllowPermittedResources() {
            return allowPermittedResources;
        }

        public void setAllowPermittedResources(List<String> allowPermittedResources) {
            this.allowPermittedResources = allowPermittedResources;
        }
    }

    public static final String ERR_NOT_PERMITTED_RESOURCE = "not allowed resource parameter value";
    public static final String ERR_NO_RESOURCE_IN_TOKEN_REQUEST = "resource parameter value in token request does not exist.";
    public static final String ERR_DIFFERENT_RESOURCE = "resource parameter value in token request does not match the one in authorization request.";

    public ResourceAudienceBindExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return ConfidentialClientAcceptExecutorFactory.PROVIDER_ID;
    }

    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Profile.Feature.RESOURCE_TOKEN_AUDIENCE_BIND)) {
            logger.warnf("RESOURCE_TOKEN_AUDIENCE_BIND feature is disabled. So the executor does not work. " +
                    "Please enable RESOURCE_TOKEN_AUDIENCE_BIND feature in order to be able to have token audience binding with resource parameter applied.");
            return;
        }

        switch (context.getEvent()) {
            case AUTHORIZATION_REQUEST:
                AuthorizationRequestContext authzRequestContext = (AuthorizationRequestContext) context;
                String resourceParam = authzRequestContext.getAuthorizationEndpointRequest().getResource();
                logger.infov("EXECUTOR on authz request: resourceParam = {0}", resourceParam);
                List<String> allowResourceList = convertContentFilledList(configuration.getAllowPermittedResources());
                if (allowResourceList != null && !allowResourceList.isEmpty()) {
                    if (!allowResourceList.contains(resourceParam)) {
                        logger.warnv("not allowed resource parameter value: resource = {0}", resourceParam);
                        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, ERR_NOT_PERMITTED_RESOURCE);
                    }
                }
                return;
            case TOKEN_REQUEST:
                checkResourceParameterValue((TokenRequestContext) context);
                return;
            default:
        }
    }

    /**
     * When the authorization request does not include resource parameter but the token request includes that,
     * the resource parameter in the token request is ignored, not set to audience claim in an access token.
     */
    private void checkResourceParameterValue(TokenRequestContext context) throws ClientPolicyException {
        String resourceInTokenRequest = context.getParams().getFirst(OAuth2Constants.RESOURCE);
        AuthenticatedClientSessionModel clientSession = context.getParseResult().getClientSession();
        if (clientSession == null) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT, "client session is null");
        }
        String resourceInAuthorizationRequest = clientSession.getNote(OAuth2Constants.RESOURCE);

        logger.infov("EXECUTOR on token request: resourceInAuthorizationRequest = {0}", resourceInAuthorizationRequest);

        if (resourceInAuthorizationRequest == null) {
            return;
        }

        if (resourceInTokenRequest == null) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, ERR_NO_RESOURCE_IN_TOKEN_REQUEST);
        }

        if (!resourceInTokenRequest.equals(resourceInAuthorizationRequest)) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, ERR_DIFFERENT_RESOURCE);
        }
    }

    protected List<String> convertContentFilledList(List<String> list) {
        if (list == null) {
            return Collections.emptyList();
        }
        return list.stream().filter(Objects::nonNull).filter(i->!i.isBlank()).distinct().toList();
    }

    /**
     * creates a protocol mapper that cannot be modified by administration users and that is used to bind AccessTokens
     * to a resource parameter of an authorization and token request. <br />
     */
    public static Stream<Map.Entry<ProtocolMapperModel, ProtocolMapper>> getTransientProtocolMapper() {
        ProtocolMapperModel protocolMapperModel = new ProtocolMapperModel();
        protocolMapperModel.setId("resource-token-audience-bind");
        protocolMapperModel.setName("resource-token-audience-bind");
        protocolMapperModel.setProtocolMapper(ResourceAudienceProtocolMapper.PROVIDER_ID);
        protocolMapperModel.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "false");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "false");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, "true");
        protocolMapperModel.setConfig(config);

        ProtocolMapper protocolMapper = new ResourceAudienceBindExecutor.ResourceAudienceProtocolMapper();
        return Stream.of(Map.entry(protocolMapperModel, protocolMapper));
    }

    /**
     * a custom protocol mapper that is not meant for configuration in the Admin-UI. This mapper is created on the
     * fly for TokenRequests to bind the created generated AccessTokens to a resource parameter of an authorization and token request.
     *
     * <p>By following RFC 8707 resource indicator, add specified audience by resource parameter of an authorization request to the audience (aud) field of token
     */
    private static final class ResourceAudienceProtocolMapper extends AbstractOIDCProtocolMapper
            implements OIDCAccessTokenMapper, OIDCIDTokenMapper, TokenIntrospectionTokenMapper, OIDCAccessTokenResponseMapper {

        private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

        static {
            OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, AudienceProtocolMapper.class);

            // Don't include audience in ID Token by default
            for (ProviderConfigProperty prop : configProperties) {
                if (OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN.equals(prop.getName())) {
                    prop.setDefaultValue("false");
                }
            }
        }

        public static final String PROVIDER_ID = "resource-audience-mapper";

        public List<ProviderConfigProperty> getConfigProperties() {
            return configProperties;
        }

        @Override
        public String getId() {
            return PROVIDER_ID;
        }

        @Override
        public String getDisplayType() {
            return "Resource Audience";
        }

        @Override
        public String getDisplayCategory() {
            return TOKEN_MAPPER_CATEGORY;
        }

        @Override
        public String getHelpText() {
            return "not shown";
        }

        @Override
        protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
            if (clientSessionCtx == null || clientSessionCtx.getClientSession() == null) return;
            String audienceValue = clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class);
            logger.infov("EXECUTOR mapper: audienceValueNote = {0}", audienceValue);
            if (audienceValue == null) return;
            token.addAudience(audienceValue);
        }
    }
}
