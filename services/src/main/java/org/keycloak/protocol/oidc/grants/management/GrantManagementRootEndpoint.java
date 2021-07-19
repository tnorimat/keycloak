/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
 *
 */
package org.keycloak.protocol.oidc.grants.management;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.common.Profile;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.protocol.oidc.ext.OIDCExtProvider;
import org.keycloak.protocol.oidc.ext.OIDCExtProviderFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;

/**
 * Grant Management Root Endpoint
 */
public class GrantManagementRootEndpoint implements OIDCExtProvider, OIDCExtProviderFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "grants";

    private final KeycloakSession session;
    private EventBuilder event;

    public GrantManagementRootEndpoint() {
        // for reflection
        this(null);
    }

    public static UriBuilder grantManagementUrl(UriBuilder baseUriBuilder) {
        UriBuilder uriBuilder = OIDCLoginProtocolService.tokenServiceBaseUrl(baseUriBuilder);
        return uriBuilder.path(OIDCLoginProtocolService.class, "resolveExtension").resolveTemplate("extension", GrantManagementRootEndpoint.PROVIDER_ID, false).path("/");
    }

    public GrantManagementRootEndpoint(KeycloakSession session) {
        this.session = session;
    }

    /**
     * The Grant Query Endpoint to query a grant
     *
     * @return
     */
    @Path("query")
    public GrantManagementQueryEndpoint queryGrant() {
        GrantManagementQueryEndpoint endpoint = new GrantManagementQueryEndpoint(session, event);

        ResteasyProviderFactory.getInstance().injectProperties(endpoint);

        return endpoint;
    }

    /**
     * The Grant Revoke Endpoint to revoke a grant
     *
     * @return
     */
    @Path("revoke")
    public GrantManagementRevokeEndpoint revokeGrant() {
        GrantManagementRevokeEndpoint endpoint = new GrantManagementRevokeEndpoint(session, event);

        ResteasyProviderFactory.getInstance().injectProperties(endpoint);

        return endpoint;
    }

    @Override
    public OIDCExtProvider create(KeycloakSession session) {
        return new GrantManagementRootEndpoint(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void setEvent(EventBuilder event) {
        this.event = event;
    }

    @Override
    public void close() {

    }

    @Override
    public boolean isSupported() {
        return Profile.isFeatureEnabled(Profile.Feature.GRANT_MANAGEMENT);
    }

}
