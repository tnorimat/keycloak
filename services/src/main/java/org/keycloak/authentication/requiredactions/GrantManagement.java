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

package org.keycloak.authentication.requiredactions;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserGrantModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.GrantManagementProvider;
import org.keycloak.models.UserConsentModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.management.Constants;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.HashSet;
import java.util.Set;


public class GrantManagement implements RequiredActionProvider {
    private static final Logger logger = Logger.getLogger(GrantManagement.class);
    public static final String GRANT_ACCEPTED = "grantAccepted";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        String grantAccepted = context.getAuthenticationSession().getClientNote(GRANT_ACCEPTED);
        if (grantAccepted != null) {
            context.getAuthenticationSession().removeAuthNote(GRANT_ACCEPTED);
            return;
        }

        String grantManagementAction = context.getAuthenticationSession().getAuthNote(OIDCLoginProtocol.GRANT_MANAGEMENT_ACTION);

        if(Constants.GRANT_MANAGEMENT_ACTIONS_SUPPORTED_BY_AUTHZ_REQUEST.contains(grantManagementAction)) {

            context.getUser().addRequiredAction(GrantManagementFactory.PROVIDER_ID);
            logger.debug("User is required to accept or reject the grant");
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {

        String authorizationDetails = context.getAuthenticationSession().getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM);
        //the authorizationDetails coming from client can be enriched with data coming from a resource server
        //TODO: when merge with RAR branch, Response challenge = context.form()
        // .setAttribute("authorizationDetail", rarProcessor.enrich(authorizationDetail))
        Response challenge = context.form()
                .setAttribute("authorizationDetails", authorizationDetails)
                .createForm("grant-required.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent().clone().event(EventType.GRANT_CONSENT).detail(Details.CONSENT, context.getUser().getUsername());
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        UserModel user = authSession.getAuthenticatedUser();
        ClientModel client = authSession.getClient();
        RealmModel realm = context.getRealm();

        if (formData.containsKey("cancel")) {
            cleanSession(context, RequiredActionContext.KcActionStatus.CANCELLED);
            context.failure();
            event.error(Errors.CONSENT_DENIED);
            return;
        }

        String grantId = authSession.getAuthNote(OIDCLoginProtocol.GRANT_ID_PARAM);
        GrantManagementProvider grantManagementProvider = context.getSession().getProvider(GrantManagementProvider.class);
        long currentTime = Time.currentTimeMillis();


        String grantManagementAction = context.getAuthenticationSession().getAuthNote(OIDCLoginProtocol.GRANT_MANAGEMENT_ACTION);
        UserGrantModel userGrantModel = null;

        //grant management action not supported
        if (!Constants.GRANT_MANAGEMENT_ACTIONS_SUPPORTED_BY_AUTHZ_REQUEST.contains(grantManagementAction)) {

            cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
            context.failure();
            event.error(Errors.INVALID_REQUEST);
            return;
        }

        //grantId required when it is an update or replace
        if (Constants.GRANT_MANAGEMENT_ACTION_UPDATE.equals(grantManagementAction)
                || Constants.GRANT_MANAGEMENT_ACTION_REPLACE.equals(grantManagementAction)) {

            if ((grantId == null || grantId.length() == 0)) {
                cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
                context.failure();
                event.error(Errors.INVALID_GRANT_ID);
                return;
            }

            try {
                userGrantModel = grantManagementProvider.getGrantByGrantIdAndClientId(realm, grantId, client.getClientId());
            } catch (Exception e) {
                cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
                context.failure();
                event.error(Errors.INVALID_REQUEST);
                return;
            }
            if (userGrantModel == null || !userGrantModel.getUserId().equals(user.getId())) {
                cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
                context.failure();
                event.error(Errors.INVALID_GRANT_ID);
                return;
            }
        }

        //it should have a consent between user and client
        UserConsentModel grantedConsent = context.getSession().users().getConsentByClient(realm, user.getId(), client.getId());
        if (grantedConsent == null) {
            grantedConsent = new UserConsentModel(client);
            context.getSession().users().addConsent(realm, user.getId(), grantedConsent);
        }

        Set<String> grantScopes = new HashSet<String>();
        boolean updateConsentRequired = false;
        for (String clientScopeId : authSession.getClientScopes()) {
            ClientScopeModel clientScope = KeycloakModelUtils.findClientScopeById(realm, client, clientScopeId);
            if (clientScope != null) {
                if (!grantedConsent.isClientScopeGranted(clientScope) && clientScope.isDisplayOnConsentScreen()) {
                    grantedConsent.addGrantedClientScope(clientScope);
                    updateConsentRequired = true;
                }

                if (grantedConsent.isClientScopeGranted(clientScope)) {
                    grantScopes.add(clientScope.getName());
                }
            } else {
                logger.warnf("Client scope or client with ID '%s' not found", clientScopeId);
            }
        }

        if (updateConsentRequired) {
            context.getSession().users().updateConsent(realm, user.getId(), grantedConsent);
        }

        if (Constants.GRANT_MANAGEMENT_ACTION_CREATE.equals(grantManagementAction)) {
            try {

                userGrantModel = new UserGrantModel();
                grantId = Base64Url.encode(KeycloakModelUtils.generateSecret());
                userGrantModel.setGrantId(grantId);
                userGrantModel.setClientId(client.getClientId());
                userGrantModel.setUserId(user.getId());
                userGrantModel.setScopes(grantScopes);
                userGrantModel.setClaims(authSession.getAuthNote(OIDCLoginProtocol.CLAIMS_PARAM));
                //TODO: when merging with RAR, userGrantModel.setAuthorizationDetails(rarProcessor.finaliseAuthorizationDetails(grantManagementAction, formData, authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM)));
                userGrantModel.setAuthorizationDetails(authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM));
                userGrantModel.setCreatedDate(currentTime);
                userGrantModel.setLastUpdatedDate(currentTime);
                grantManagementProvider.adduserGrant(realm, userGrantModel);

            } catch (Exception e) {
                cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
                context.failure();
                event.error(Errors.INVALID_REQUEST);
                return;
            }
        }

        if (Constants.GRANT_MANAGEMENT_ACTION_REPLACE.equals(grantManagementAction)) {

            try {
                userGrantModel.setScopes(grantScopes);
                userGrantModel.setClaims(authSession.getAuthNote(OIDCLoginProtocol.CLAIMS_PARAM));
                //TODO: when merging with RAR, userGrantModel.setAuthorizationDetails(rarProcessor.finaliseAuthorizationDetails(grantManagementAction, formData, authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM)));
                userGrantModel.setAuthorizationDetails(authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM));
                userGrantModel.setLastUpdatedDate(currentTime);
                grantManagementProvider.updateUserGrant(realm, userGrantModel);

            } catch (Exception e) {
                cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
                context.failure();
                event.error(Errors.INVALID_REQUEST);
                return;
            }
        }

        if (Constants.GRANT_MANAGEMENT_ACTION_UPDATE.equals(grantManagementAction)) {

            try {

                if (userGrantModel.getScopes() == null || userGrantModel.getScopes().isEmpty()) {
                    userGrantModel.setScopes(grantScopes);
                }else {
                    userGrantModel.getScopes().addAll(grantScopes);
                }

                userGrantModel.setClaims(authSession.getAuthNote(OIDCLoginProtocol.CLAIMS_PARAM));
                //TODO: when merging with RAR, userGrantModel.setAuthorizationDetails(rarProcessor.finaliseAuthorizationDetails(grantManagementAction, formData, authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM)));
                userGrantModel.setAuthorizationDetails(authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM));
                userGrantModel.setLastUpdatedDate(currentTime);
                grantManagementProvider.updateUserGrant(realm, userGrantModel);

            } catch (Exception e) {
                cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
                context.failure();
                event.error(Errors.INVALID_REQUEST);
                return;
            }
        }

        cleanSession(context, RequiredActionContext.KcActionStatus.SUCCESS);
        authSession.setClientNote(OIDCLoginProtocol.GRANT_ID_PARAM, grantId);
        authSession.setClientNote(GRANT_ACCEPTED, GRANT_ACCEPTED);
        context.success();
    }

    private void cleanSession(RequiredActionContext context, RequiredActionContext.KcActionStatus status) {
        context.getAuthenticationSession().removeRequiredAction(GrantManagementFactory.PROVIDER_ID);
        context.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
        AuthenticationManager.setKcActionStatus(GrantManagementFactory.PROVIDER_ID, status, context.getAuthenticationSession());
    }

    @Override
    public void close() {

    }
}
