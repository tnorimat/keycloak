/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.grant.jpa;

import org.keycloak.models.jpa.entities.UserConsentEntity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

@NamedQueries({
        @NamedQuery(name="userGrantByGrantIdAndUserId", query="select userGrant from UserGrantEntity userGrant where userGrant.grantId = :grantId and userGrant.userId = :userId"),
        @NamedQuery(name="deleteUserGrantByGrantIdAndUserId", query="delete from UserGrantEntity userGrant where userGrant.grantId = :grantId and userGrant.userId = :userId"),
})
@Entity
@Table(name="USER_GRANT")
@IdClass(UserGrantEntity.Key.class)
public class UserGrantEntity {

    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name = "USER_CONSENT_ID")
    protected UserConsentEntity userConsent;

    @Id
    @Column(name="GRANT_ID")
    protected String grantId;

    @Column(name="USER_ID")
    protected String userId;

    @Column(name="SCOPES")
    protected String scopes;

    @Column(name="CLAIMS")
    protected String claims;

    @Column(name="AUTHORIZATION_DETAILS")
    protected String authorization_details;

    @Column(name = "CREATED_DATE")
    private Long createdDate;

    @Column(name = "LAST_UPDATED_DATE")
    private Long lastUpdatedDate;

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

    public String getGrantId() {
        return grantId;
    }

    public void setGrantId(String grantId) {
        this.grantId = grantId;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public String getClaims() {
        return claims;
    }

    public void setClaims(String claims) {
        this.claims = claims;
    }

    public String getAuthorization_details() {
        return authorization_details;
    }

    public void setAuthorization_details(String authorization_details) {
        this.authorization_details = authorization_details;
    }

    public UserConsentEntity getUserConsent() {
        return userConsent;
    }

    public void setUserConsent(UserConsentEntity userConsent) {
        this.userConsent = userConsent;
    }

    

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserGrantEntity)) return false;

        UserGrantEntity that = (UserGrantEntity)o;
        UserGrantEntity.Key myKey = new UserGrantEntity.Key(this.userConsent, this.grantId);
        UserGrantEntity.Key hisKey = new UserGrantEntity.Key(that.userConsent, that.grantId);
        return myKey.equals(hisKey);
    }

    @Override
    public int hashCode() {
        UserGrantEntity.Key myKey = new UserGrantEntity.Key(this.userConsent, this.grantId);
        return myKey.hashCode();
    }

    public static class Key implements Serializable {

        protected UserConsentEntity userConsent;

        protected String grantId;

        public Key() {
        }

        public Key(UserConsentEntity userConsent, String grantId) {
            this.userConsent = userConsent;
            this.grantId = grantId;
        }

        public UserConsentEntity getUserConsent() {
            return userConsent;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            UserGrantEntity.Key key = (UserGrantEntity.Key) o;

            if (userConsent != null ? !userConsent.getId().equals(key.userConsent != null ? key.userConsent.getId() : null) : key.userConsent != null) return false;
            if (grantId != null ? !grantId.equals(key.grantId) : key.grantId != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = userConsent != null ? userConsent.getId().hashCode() : 0;
            result = 31 * result + (grantId != null ? grantId.hashCode() : 0);
            return result;
        }
    }

    public UserGrantEntity(String grantId, String userId, String scopes, String claims, String authorization_details) {
        this.grantId = grantId;
        this.userId = userId;
        this.scopes = scopes;
        this.claims = claims;
        this.authorization_details = authorization_details;
    }

    public UserGrantEntity() {
    }
}
