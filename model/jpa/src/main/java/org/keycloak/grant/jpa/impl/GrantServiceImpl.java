/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.grant.jpa.impl;

import org.keycloak.models.*;
import org.keycloak.grant.jpa.UserGrantEntity;
import org.keycloak.models.jpa.entities.UserConsentEntity;
import org.keycloak.storage.StorageId;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.persistence.TypedQuery;
import java.util.List;

public class GrantServiceImpl implements GrantService {

    private final KeycloakSession session;
    protected EntityManager em;

    public GrantServiceImpl(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.em = em;
        if (getRealm() == null) {
            throw new IllegalStateException("The service cannot accept a session without a realm in its context.");
        }
    }

    protected RealmModel getRealm() {
        return session.getContext().getRealm();
    }


    @Override
    public boolean revokeGrantByGrantId(RealmModel realm, String grandId, String userId) {
        UserGrantEntity userGrant = getUserGrantEntity(grandId, userId, LockModeType.PESSIMISTIC_WRITE);
        if (userGrant == null) return false;

        em.remove(userGrant);
        em.flush();
        return true;
    }

    @Override
    public UserGrantModel getGrantByGrantId(RealmModel realm, String grandId, String userId) {
        UserGrantEntity userGrant = getUserGrantEntity(grandId, userId, LockModeType.NONE);
        if (userGrant == null) {
            throw new ModelException("Grant not found for [" + grandId + "]");
        }
        return new UserGrantModel(userGrant.getScopes(), userGrant.getClaims(), userGrant.getAuthorization_details(), userGrant.getGrantId(), userGrant.getCreatedDate(), userGrant.getLastUpdatedDate());
    }

    @Override
    public void adduserGrant(RealmModel realm, String userId, String clientId, UserGrantModel userGrantModel) {

        UserGrantEntity userGrantEntity = new UserGrantEntity(userGrantModel.getGrantId(), userId, userGrantModel.getScopes(), userGrantModel.getClaims(), userGrantModel.getAuthorizationDetails());
        userGrantEntity.setCreatedDate(System.currentTimeMillis());

        userGrantEntity.setUserConsent(em.getReference(UserConsentEntity.class, userGrantModel.getUserConsentId()));

        em.persist(userGrantEntity);
        em.flush();
    }

    @Override
    public void updateUserGrant(RealmModel realm, String userId, String clientId, UserGrantModel userGrantModel) {
        UserGrantEntity userGrantEntity = getUserGrantEntity(userGrantModel.getGrantId(), userId, LockModeType.NONE);
        if (userGrantEntity == null) {
            throw new ModelException("Grant not found for [" + userGrantModel.getGrantId() + "]");
        }
        userGrantEntity.setClaims(userGrantModel.getClaims());
        userGrantEntity.setScopes(userGrantModel.getScopes());
        userGrantEntity.setAuthorization_details(userGrantModel.getAuthorizationDetails());
        userGrantEntity.setLastUpdatedDate(System.currentTimeMillis());

        em.persist(userGrantEntity);
        em.flush();
    }

    private UserGrantEntity getUserGrantEntity(String grandId, String userId, LockModeType lockMode) {
        TypedQuery<UserGrantEntity> query = em.createNamedQuery("userGrantByGrantIdAndUserId", UserGrantEntity.class);
        query.setParameter("grantId", grandId);
        query.setParameter("userId", userId);
        query.setLockMode(lockMode);
        List<UserGrantEntity> results = query.getResultList();
        if (results.isEmpty()) {
            return null;
        } else if (results.size() > 1) {
            throw new IllegalStateException("More results found for grandId=" + grandId);
        } else {
            UserGrantEntity userGrant = results.get(0);
            return userGrant;
        }
    }


    @Override
    public void close() {

    }
}
