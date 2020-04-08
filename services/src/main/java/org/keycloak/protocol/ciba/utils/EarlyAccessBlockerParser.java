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
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.ciba.EarlyAccessBlockerStore;

public class EarlyAccessBlockerParser {

    private static final Logger logger = Logger.getLogger(EarlyAccessBlockerParser.class);

    public static void persistEarlyAccessBlocker(KeycloakSession session, String id, EarlyAccessBlocker earlyAccessBlockerData, int expires_in) {
        if (id == null) {
            throw new IllegalStateException("ID not present in the data");
        }
        UUID key = UUID.fromString(id);

        Map<String, String> serialized = earlyAccessBlockerData.serializeCode();
        EarlyAccessBlockerStore.put(key, expires_in, serialized);
 
        // to prevent expired entries from being stacked infinitely.
        EarlyAccessBlockerStore.sweepExpiredEntries();
    }

    public static ParseResult parseEarlyAccessBlocker(KeycloakSession session, String id) {
        ParseResult result = new ParseResult(id);

        // Parse UUID
        UUID storeKeyUUID;
        try {
            storeKeyUUID = UUID.fromString(id);
        } catch (IllegalArgumentException re) {
            logger.warn("Invalid format of the UUID in the code");
            return null;
        }

        Map<String, String> earlyAccessBlockerData = EarlyAccessBlockerStore.remove(storeKeyUUID);

        if (earlyAccessBlockerData == null) return result.notFoundEarlyAccessBlocker();

        result.earlyAccessBlockerData = EarlyAccessBlocker.deserializeCode(earlyAccessBlockerData);

        // Finally doublecheck if code is not expired
        int currentTime = Time.currentTime();
        if (currentTime > result.earlyAccessBlockerData.getExpiration()) {
            return result.expiredEarlyAccessBlocker();
        }

        return result;
    }

    public static void sweepExpiredEarlyAccessBlockers() {
    }

    public static class ParseResult {

        private final String id;
        private EarlyAccessBlocker earlyAccessBlockerData;

        private boolean isNotFoundEarlyAccessBlocker = false;
        private boolean isExpiredEarlyAccessBlocker = false;

        private ParseResult(String id, EarlyAccessBlocker earlyAccessBlockerData) {
            this.id = id;
            this.earlyAccessBlockerData = earlyAccessBlockerData;
        }

        private ParseResult(String id) {
            this.id = id;
        }

        public EarlyAccessBlocker earlyAccessBlockerData() {
            return earlyAccessBlockerData;
        }

        public boolean isNotFoundEarlyAccessBlocker() {
            return isNotFoundEarlyAccessBlocker;
        }

        public boolean isExpiredEarlyAccessBlocker() {
            return isExpiredEarlyAccessBlocker;
        }

        private ParseResult notFoundEarlyAccessBlocker() {
            this.isNotFoundEarlyAccessBlocker = true;
            return this;
        }

        private ParseResult expiredEarlyAccessBlocker() {
            this.isExpiredEarlyAccessBlocker = true;
            return this;
        }
    }
}
