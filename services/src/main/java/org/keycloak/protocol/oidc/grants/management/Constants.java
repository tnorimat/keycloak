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

import java.util.Arrays;
import java.util.List;

public final class Constants {

    //grants Realm Attributes Keys
    public static final String GRANT_MANAGEMENT = "grant_management.grants";

    public static final String GRANT_MANAGEMENT_ACTION_QUERY = "query";
    public static final String GRANT_MANAGEMENT_ACTION_REVOKE = "revoke";
    public static final String GRANT_MANAGEMENT_ACTION_UPDATE = "update";
    public static final String GRANT_MANAGEMENT_ACTION_REPLACE = "replace";
    public static final String GRANT_MANAGEMENT_ACTION_CREATE = "create";
    public static final List<String> GRANT_MANAGEMENT_ACTIONS = Arrays.asList(GRANT_MANAGEMENT_ACTION_QUERY, GRANT_MANAGEMENT_ACTION_REVOKE, GRANT_MANAGEMENT_ACTION_UPDATE, GRANT_MANAGEMENT_ACTION_REPLACE, GRANT_MANAGEMENT_ACTION_CREATE);
    public static final List<String> GRANT_MANAGEMENT_ACTIONS_SUPPORTED_BY_AUTHZ_REQUEST = Arrays.asList(GRANT_MANAGEMENT_ACTION_UPDATE, GRANT_MANAGEMENT_ACTION_REPLACE, GRANT_MANAGEMENT_ACTION_CREATE);

    public static final String GRANT_MANAGEMENT_ACTION_QUERY_SCOPE = "grant_management_query";
    public static final String GRANT_MANAGEMENT_ACTION_REVOKE_SCOPE = "grant_management_revoke";
}
