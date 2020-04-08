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
package org.keycloak.protocol.ciba;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class EarlyAccessBlockerStore {

    private final static ConcurrentMap<UUID, EarlyAccessBlockerValueEntity> blockerCache = new ConcurrentHashMap<>();

    public static void put(UUID blockerId, int lifespanSeconds, Map<String, String> blockerData) {
        EarlyAccessBlockerValueEntity blockerValue = new EarlyAccessBlockerValueEntity(blockerData);
        blockerCache.put(blockerId, blockerValue);
    }

    public static Map<String, String> remove(UUID codeId) {
        EarlyAccessBlockerValueEntity existing = blockerCache.remove(codeId);
        return existing == null ? null : existing.getNotes();
    }
}
