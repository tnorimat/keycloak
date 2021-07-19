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

import org.keycloak.Config.Scope;
import org.keycloak.models.GrantManagementProvider;
import org.keycloak.models.GrantManagementProviderFactory;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakSessionFactory;


public class DefaultGrantManagementProviderFactory implements GrantManagementProviderFactory {

    @Override
    public GrantManagementProvider create(KeycloakSession session) {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        return new DefaultGrantManagementProvider(session, realm);
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "DefaultGrantManagementProvider";
    }

}
