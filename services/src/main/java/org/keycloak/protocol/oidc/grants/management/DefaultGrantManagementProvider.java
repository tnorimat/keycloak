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



import org.keycloak.models.GrantManagementProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserGrantModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class DefaultGrantManagementProvider implements GrantManagementProvider {

    private final KeycloakSession session;
    private final RealmModel realm;

    public DefaultGrantManagementProvider(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    @Override
    public boolean revokeGrantByGrantId(RealmModel realm, String grantId, String clientId) {
        try {
            GrantsRepresentation grantsRepresentation = getGrantsRepresentation(realm);
            List<UserGrantModel> grants = grantsRepresentation.getGrants();
            UserGrantModel userGrantModel = grants.stream()
                    .filter(grant -> grant.getGrantId().equals(grantId) && grant.getClientId().equals(clientId))
                    .findFirst().orElse(null);

            if ( userGrantModel != null) {
                grants.remove(userGrantModel);
                setGrantsJsonString(realm, convertGrantsRepresentationToJson(grantsRepresentation));
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean revokeGrantByClientIdAndUserId(RealmModel realm, String userId, String clientId) {
        try {
            GrantsRepresentation grantsRepresentation = getGrantsRepresentation(realm);
            List<UserGrantModel> grants = grantsRepresentation.getGrants();
            List<UserGrantModel> userGrantsToRevoke = grants.stream()
                    .filter(grant -> grant.getUserId().equals(userId) && grant.getClientId().equals(clientId))
                    .collect(Collectors.toList());

            userGrantsToRevoke.forEach( grantToRevoke -> {
                grants.remove(grantToRevoke);
            });
            setGrantsJsonString(realm, convertGrantsRepresentationToJson(grantsRepresentation));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public UserGrantModel getGrantByGrantIdAndClientId(RealmModel realm, String grantId, String clientId) throws Exception {
        GrantsRepresentation grantsRepresentation = getGrantsRepresentation(realm);
        UserGrantModel userGrantModel = grantsRepresentation.getGrants().stream()
                .filter(grant -> grant.getGrantId().equals(grantId) && grant.getClientId().equals(clientId))
                .findFirst().orElse(null);

        return  userGrantModel;
    }

    @Override
    public void adduserGrant(RealmModel realm, UserGrantModel userGrantModel) throws Exception {
        GrantsRepresentation grantsRepresentation = getGrantsRepresentation(realm);
        grantsRepresentation.getGrants().add(userGrantModel);
        setGrantsJsonString(realm, convertGrantsRepresentationToJson(grantsRepresentation));
    }

    @Override
    public void updateUserGrant(RealmModel realm, UserGrantModel updatedGrantModel) throws Exception {
        GrantsRepresentation grantsRepresentation = getGrantsRepresentation(realm);
        List<UserGrantModel> grants = grantsRepresentation.getGrants();
        UserGrantModel persistedGrantModel = grants.stream()
                .filter(grant -> grant.getGrantId().equals(updatedGrantModel.getGrantId()))
                .findFirst().orElse(null);
        grants.remove(persistedGrantModel);
        grants.add(updatedGrantModel);
        setGrantsJsonString(realm, convertGrantsRepresentationToJson(grantsRepresentation));
    }

    @Override
    public void close() {

    }

    private GrantsRepresentation getGrantsRepresentation(RealmModel realm) throws Exception {
        String grantsJson = getGrantsJsonString(realm);

        if(grantsJson == null) {
            return new GrantsRepresentation();
        }
        return convertGrantsJsonToRepresentation(grantsJson);
    }

    private String convertGrantsRepresentationToJson(GrantsRepresentation grantsRepresentation) throws Exception {
        try {
            return JsonSerialization.writeValueAsString(grantsRepresentation);
        } catch (IOException ioe) {
            throw new Exception(ioe.getMessage());
        }
    }

    private GrantsRepresentation convertGrantsJsonToRepresentation(String json) throws Exception {
        try {
            return JsonSerialization.readValue(json, GrantsRepresentation.class);
        } catch (IOException ioe) {
            throw new Exception(ioe.getMessage());
        }
    }

    private String getGrantsJsonString(RealmModel realm) {
        return realm.getAttribute(Constants.GRANT_MANAGEMENT);
    }

    private void setGrantsJsonString(RealmModel realm, String json) {
        realm.setAttribute(Constants.GRANT_MANAGEMENT, json);
    }
}
