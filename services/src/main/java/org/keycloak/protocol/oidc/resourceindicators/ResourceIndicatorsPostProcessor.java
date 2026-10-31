package org.keycloak.protocol.oidc.resourceindicators;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.token.TokenInterceptorException;
import org.keycloak.protocol.oidc.token.TokenPostProcessor;
import org.keycloak.protocol.oidc.token.TokenPostProcessorContext;

public class ResourceIndicatorsPostProcessor implements TokenPostProcessor {

    private final KeycloakSession session;

    public ResourceIndicatorsPostProcessor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void process(TokenPostProcessorContext context) {
        List<String> requestedResources = getRequestedResources(context);
        for (String requestedResource : requestedResources) {
            if (!ResourceIndicatorValidation.isValidResourceIndicator(requestedResource)) {
                throw new TokenInterceptorException(OAuthErrorException.INVALID_TARGET, ResourceIndicatorConstants.ERROR_INVALID_RESOURCE);
            }
        }

        String grantType = context.clientSessionCtx().getAttribute(Constants.GRANT_TYPE, String.class);

        boolean originalResourcesRequired = false;
        List<String> originalResources = List.of();
        if (OAuth2Constants.AUTHORIZATION_CODE.equals(grantType)) {
            originalResources = ResourceIndicatorUtils.split(context.code().getResource());
            originalResourcesRequired = true;
        } else if (OAuth2Constants.REFRESH_TOKEN.equals(grantType)) {
            originalResources = ResourceIndicatorUtils.fromClaim(context.requestRefreshToken().getOtherClaims().get(OAuth2Constants.RESOURCE));
            originalResourcesRequired = true;
        }

        if (originalResources.isEmpty() && requestedResources.isEmpty()) {
            return;
        }

        // Resources the grant is bound to. A refresh token keeps all of them so that the client can later
        // request an access token for any of them (RFC 8707 Section 2.2).
        List<String> grantedResources = requestedResources;
        if (originalResourcesRequired) {
            if (originalResources.isEmpty()) {
                throw new TokenInterceptorException(OAuthErrorException.INVALID_TARGET, ResourceIndicatorConstants.ERROR_NOT_MATCHING);
            }

            if (requestedResources.isEmpty()) {
                requestedResources = originalResources;
            } else if (!originalResources.containsAll(requestedResources)) {
                throw new TokenInterceptorException(OAuthErrorException.INVALID_TARGET, ResourceIndicatorConstants.ERROR_NOT_MATCHING);
            }
            grantedResources = originalResources;
        }

        String[] audience = context.accessToken().getAudience();
        Set<String> audienceToSet = new LinkedHashSet<>();
        for (String requestedResource : requestedResources) {
            String resolvedAudience = resolveAudience(requestedResource, audience);
            if (resolvedAudience == null) {
                throw new TokenInterceptorException(OAuthErrorException.INVALID_TARGET, ResourceIndicatorConstants.ERROR_INVALID_RESOURCE);
            }
            audienceToSet.add(resolvedAudience);
        }

        if (context.refreshToken() != null) {
            context.refreshToken().getOtherClaims().put(OAuth2Constants.RESOURCE, ResourceIndicatorUtils.toClaim(grantedResources));
        }
        context.accessToken().audience(audienceToSet.toArray(String[]::new));
    }

    private List<String> getRequestedResources(TokenPostProcessorContext context) {
        List<?> requested = context.clientSessionCtx().getAttribute(OAuth2Constants.RESOURCE, List.class);
        if (requested == null || requested.isEmpty()) {
            return List.of();
        }
        return requested.stream().map(String::valueOf).distinct().toList();
    }

    private String resolveAudience(String requestedResource, String[] audience) {
        if (audience == null) {
            return null;
        }
        if (isClientUrn(requestedResource)) {
            return findAudienceByClientUrn(requestedResource, audience);
        }
        String audienceToSet = findCustomAudience(requestedResource, audience);
        if (audienceToSet == null) {
            audienceToSet = findAudienceByClientAttribute(requestedResource, audience);
        }
        return audienceToSet;
    }

    private boolean isClientUrn(String resource) {
        return resource.startsWith(ResourceIndicatorConstants.URN_CLIENT_PREFIX);
    }

    private String findAudienceByClientUrn(String resource, String[] audience) {
        String requestedClientId = resource.substring(ResourceIndicatorConstants.URN_CLIENT_PREFIX.length());
        return find(requestedClientId, audience);
    }

    private String findAudienceByClientAttribute(String resource, String[] audience) {
        for (String a : audience) {
            ClientModel client = session.clients().getClientByClientId(session.getContext().getRealm(), a);
            if (client != null) {
                String clientResourceUrl = client.getAttribute(ResourceIndicatorConstants.CLIENT_RESOURCE_URL_ATTRIBUTE);
                if (resource.equals(clientResourceUrl)) {
                    return resource;
                }
            }
        }
        return null;
    }

    private String findCustomAudience(String resource, String[] audience) {
        // Direct match against existing token audiences (fast path to support custom audiences without DB lookups)
        return find(resource, audience);
    }

    private String find(String search, String[] array) {
        for (String a : array) {
            if (a.equals(search)) {
                return a;
            }
        }
        return null;
    }

}
