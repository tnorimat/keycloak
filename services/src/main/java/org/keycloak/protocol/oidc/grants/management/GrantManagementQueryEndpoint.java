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
 */
package org.keycloak.protocol.oidc.grants.management;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.Profile;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.GrantManagementProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserGrantModel;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resources.Cors;
import org.keycloak.utils.ProfileHelper;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class GrantManagementQueryEndpoint extends AbstractGrantManagementEndpoint {

    private final AppAuthManager appAuthManager;

    public GrantManagementQueryEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.appAuthManager = new AppAuthManager();
    }

    @Path("/{grant_id}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Response queryGrant(@PathParam("grant_id") String grantId, @Context final HttpHeaders headers) {

        ProfileHelper.requireFeature(Profile.Feature.GRANT_MANAGEMENT);
        event.event(EventType.QUERY_GRANT);
        cors = Cors.add(request).auth().allowedMethods("GET").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        checkSsl();
        checkRealm();
        authorizeClient();

        String accessToken = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
        checkToken(accessToken, Constants.GRANT_MANAGEMENT_ACTION_QUERY_SCOPE, client.getClientId());

        GrantManagementProvider grantManagementProvider = session.getProvider(GrantManagementProvider.class);

        UserGrantModel grant = null;
        try {
            grant = grantManagementProvider.getGrantByGrantIdAndClientId(realm, grantId, client.getClientId());
        } catch (Exception e) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_GRANT, e.getMessage(), Response.Status.BAD_REQUEST);
        }

        return Response.status(Response.Status.OK)
                .entity(grant)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }
}
