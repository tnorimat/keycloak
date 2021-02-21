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
package org.keycloak.protocol.ciba.utils;

import java.util.Map;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.CodeToTokenStoreProvider;
import org.keycloak.models.KeycloakSession;

public class DecoupledAuthnResultParser {

    private static final Logger logger = Logger.getLogger(DecoupledAuthnResultParser.class);

    public static void persistDecoupledAuthnResult(KeycloakSession session, String id, DecoupledAuthnResult decoupledAuthnResultData, int expires_in) {
        if (id == null) {
            throw new IllegalStateException("ID not present in the data");
        }
        UUID key = UUID.fromString(id);

        CodeToTokenStoreProvider codeStore = session.getProvider(CodeToTokenStoreProvider.class);

        Map<String, String> serialized = decoupledAuthnResultData.serializeCode();
        codeStore.put(key, expires_in, serialized);
    }

    public static ParseResult parseDecoupledAuthnResult(KeycloakSession session, String id) {
        ParseResult result = new ParseResult();

        // Parse UUID
        UUID storeKeyUUID;
        try {
            storeKeyUUID = UUID.fromString(id);
        } catch (IllegalArgumentException re) {
            logger.warn("Invalid format of the UUID in the code");
            return null;
        }

        CodeToTokenStoreProvider codeStore = session.getProvider(CodeToTokenStoreProvider.class);
        Map<String, String> decoupledAuthnResultData = codeStore.remove(storeKeyUUID);

        // Either code not available or was already used
        if (decoupledAuthnResultData == null) {
            logger.warnf("Decoupled Authn not yet completed. code = '%s'", storeKeyUUID);
            return result.notYetDecoupledAuthnResult();
        }

        result.decoupledAuthnResultData = DecoupledAuthnResult.deserializeCode(decoupledAuthnResultData);

        // Finally doublecheck if code is not expired
        if (Time.currentTime() > result.decoupledAuthnResultData.getExpiration()) {
            return result.expiredDecoupledAuthnResult();
        }

        return result;
    }

    public static class ParseResult {

        private DecoupledAuthnResult decoupledAuthnResultData;

        private boolean isNotYetDecoupledAuthnResult = false;
        private boolean isExpiredDecoupledAuthnResult = false;

        public DecoupledAuthnResult decoupledAuthnResultData() {
            return decoupledAuthnResultData;
        }

        public boolean isNotYetDecoupledAuthnResult() {
            return isNotYetDecoupledAuthnResult;
        }

        public boolean isExpiredDecoupledAuthnResult() {
            return isExpiredDecoupledAuthnResult;
        }


        private ParseResult notYetDecoupledAuthnResult() {
            this.isNotYetDecoupledAuthnResult = true;
            return this;
        }

        private ParseResult expiredDecoupledAuthnResult() {
            this.isExpiredDecoupledAuthnResult = true;
            return this;
        }
    }
}
