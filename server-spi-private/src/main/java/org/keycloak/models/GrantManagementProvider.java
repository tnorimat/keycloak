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

package org.keycloak.models;

import org.keycloak.provider.Provider;

public interface GrantManagementProvider extends Provider {

    boolean revokeGrantByGrantId(RealmModel realm, String grantId, String clientId) throws Exception;

    UserGrantModel getGrantByGrantIdAndClientId(RealmModel realm, String grantId, String clientId) throws Exception;

    void adduserGrant(RealmModel realm, UserGrantModel userGrantModel) throws Exception;

    void updateUserGrant(RealmModel realm, UserGrantModel userGrantModel) throws Exception;

    boolean revokeGrantByClientIdAndUserId(RealmModel realm, String userId, String clientId);
}
