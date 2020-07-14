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

package org.keycloak.services.clientpolicy.condition;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.clientpolicy.AdminClientRegisterContext;
import org.keycloak.services.clientpolicy.AdminClientUpdateContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.ClientPolicyVote;
import org.keycloak.services.clientpolicy.ClientUpdateContext;
import org.keycloak.services.clientpolicy.DynamicClientRegisterContext;
import org.keycloak.services.clientpolicy.DynamicClientUpdateContext;

public class UpdatingClientSourceRolesCondition implements ClientPolicyConditionProvider {

    private static final Logger logger = Logger.getLogger(UpdatingClientSourceRolesCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public UpdatingClientSourceRolesCondition(KeycloakSession session, ComponentModel componentModel) {
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
    public ClientPolicyVote applyPolicy(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
        case REGISTER:
            if (context instanceof AdminClientRegisterContext) {
                return getVoteForRolesMatched(((ClientUpdateContext)context).getAuthenticatedUser());
            } else if (context instanceof DynamicClientRegisterContext) {
                return getVoteForRolesMatched(((ClientUpdateContext)context).getToken());
            } else {
                throw new ClientPolicyException(OAuthErrorException.SERVER_ERROR, "unexpected context type.");
            }
        case UPDATE:
            if (context instanceof AdminClientUpdateContext) {
                return getVoteForRolesMatched(((ClientUpdateContext)context).getAuthenticatedUser());
            } else if (context instanceof DynamicClientUpdateContext) {
                return getVoteForRolesMatched(((ClientUpdateContext)context).getToken());
            } else {
                throw new ClientPolicyException(OAuthErrorException.SERVER_ERROR, "unexpected context type.");
            }
        default:
            return ClientPolicyVote.ABSTAIN;
        }
    }

    private ClientPolicyVote getVoteForRolesMatched(UserModel user) {
        if (isRolesMatched(user)) return ClientPolicyVote.YES;
        return ClientPolicyVote.NO;
    }

    private ClientPolicyVote getVoteForRolesMatched(JsonWebToken token) {
        if (token == null) return ClientPolicyVote.NO;
        if(isRoleMatched(token.getSubject())) return ClientPolicyVote.YES;
        return ClientPolicyVote.NO;
    }

    private boolean isRoleMatched(String subjectId) {
        if (subjectId == null) return false;
        return isRolesMatched(session.users().getUserById(subjectId, session.getContext().getRealm()));
    }

    private boolean isRolesMatched(UserModel user) {
        if (user == null) return false;

        user.getRoleMappings().stream().forEach(i -> ClientPolicyLogger.log(logger, "user role = " + i.getName()));
        componentModel.getConfig().get(UpdatingClientSourceRolesConditionFactory.ROLES).stream().forEach(i -> ClientPolicyLogger.log(logger, "roles expected = " + i));

        boolean isMatched = componentModel.getConfig().get(UpdatingClientSourceRolesConditionFactory.ROLES).stream().anyMatch(i->{
            return user.getRoleMappings().stream().anyMatch(j->j.getName().equals(i));
            });
        if (isMatched) {
            ClientPolicyLogger.log(logger, "role matched.");
        } else {
            ClientPolicyLogger.log(logger, "role unmatched.");
        }
        return isMatched;
    }

}
