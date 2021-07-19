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

import java.util.Set;

public class UserGrantModel {

    private Set<String> scopes;
    private String claims;
    private String authorizationDetails;
    private String grantId;
    private String clientId;
    private String userId;
    private Long createdDate;
    private Long lastUpdatedDate;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getClaims() {
        return claims;
    }

    public void setClaims(String claims) {
        this.claims = claims;
    }

    public String getAuthorizationDetails() {
        return authorizationDetails;
    }

    public void setAuthorizationDetails(String authorizationDetails) {
        this.authorizationDetails = authorizationDetails;
    }

    public String getGrantId() {
        return grantId;
    }

    public void setGrantId(String grantId) {
        this.grantId = grantId;
    }

    public Long getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Long createdDate) {
        this.createdDate = createdDate;
    }

    public Long getLastUpdatedDate() {
        return lastUpdatedDate;
    }

    public void setLastUpdatedDate(Long lastUpdatedDate) {
        this.lastUpdatedDate = lastUpdatedDate;
    }

    public UserGrantModel(Set<String> scopes, String claims, String authorizationDetails, String grantId, Long createdDate, Long lastUpdatedDate) {
        this.scopes = scopes;
        this.claims = claims;
        this.authorizationDetails = authorizationDetails;
        this.grantId = grantId;
        this.createdDate = createdDate;
        this.lastUpdatedDate = lastUpdatedDate;
    }

    public UserGrantModel() {
    }
}
