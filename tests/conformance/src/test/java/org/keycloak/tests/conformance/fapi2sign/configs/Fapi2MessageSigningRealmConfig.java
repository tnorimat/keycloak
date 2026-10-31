/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.tests.conformance.fapi2sign.configs;

import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.tests.conformance.fapi2.Fapi2RealmUtil;

/**
 * FAPI 2.0 Message Signing realm: every client is subject to the built-in {@code fapi-2-dpop-message-signing}
 * profile, which additionally requires signed request objects.
 */
public class Fapi2MessageSigningRealmConfig implements RealmConfig {

    @Override
    public RealmBuilder configure(RealmBuilder realm) {
        return Fapi2RealmUtil.applyCommon(realm, Fapi2RealmUtil.FAPI2_DPOP_MESSAGE_SIGNING_PROFILE);
    }
}
