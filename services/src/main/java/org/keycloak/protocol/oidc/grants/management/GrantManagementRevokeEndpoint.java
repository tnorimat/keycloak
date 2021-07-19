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
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserGrantModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resources.Cors;
import org.keycloak.utils.ProfileHelper;


import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.util.Objects;
import java.util.stream.Collectors;

public class GrantManagementRevokeEndpoint extends AbstractGrantManagementEndpoint {

    private final AppAuthManager appAuthManager;

    public GrantManagementRevokeEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.appAuthManager = new AppAuthManager();
    }

    @Path("/{grant_id}")
    @DELETE
    @NoCache
    public Response revokeGrant(@PathParam("grant_id") String grantId, @Context final HttpHeaders headers) {

        ProfileHelper.requireFeature(Profile.Feature.GRANT_MANAGEMENT);
        event.event(EventType.REVOKE_GRANT);
        cors = Cors.add(request).auth().allowedMethods("DELETE").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        checkSsl();
        checkRealm();
        authorizeClient();

        String accessToken = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
        checkToken(accessToken, Constants.GRANT_MANAGEMENT_ACTION_REVOKE_SCOPE, client.getClientId());

        GrantManagementProvider grantManagementProvider = session.getProvider(GrantManagementProvider.class);
        try {
            UserGrantModel grant = grantManagementProvider.getGrantByGrantIdAndClientId(realm, grantId, client.getClientId());
            UserModel user = session.getProvider(UserProvider.class).getUserById(realm, grant.getUserId());

            revokeClient(client, user);
            grantManagementProvider.revokeGrantByGrantId(realm, grantId, client.getClientId());

        } catch (Exception e) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_GRANT, e.getMessage(), Response.Status.BAD_REQUEST);
        }
        return Response.noContent().build();
    }


    private void revokeClient(ClientModel clientModel, UserModel user) {

        session.sessions().getUserSessionsStream(realm, user)
                .map(userSession -> userSession.getAuthenticatedClientSessionByClient(clientModel.getId()))
                .filter(Objects::nonNull)
                .collect(Collectors.toList()) // collect to avoid concurrent modification as dettachClientSession removes the user sessions.
                .forEach(clientSession -> {
                    UserSessionModel userSession = clientSession.getUserSession();
                    TokenManager.dettachClientSession(clientSession);

                    if (userSession != null) {
                        // TODO: Might need optimization to prevent loading client sessions from cache in getAuthenticatedClientSessions()
                        if (userSession.getAuthenticatedClientSessions().isEmpty()) {
                            session.sessions().removeUserSession(realm, userSession);
                        }
                    }
                });
    }
}
