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

import java.util.HashMap;
import java.util.Map;

public class DecoupledAuthnResult {
    private static final String EXPIRATION_NOTE = "exp";
    private static final String STATUS_NOTE = "status";

    private final int expiration;
    private final String status;

    public DecoupledAuthnResult(int expiration, String status) {
        this.expiration = expiration;
        this.status = status;
    }

    private DecoupledAuthnResult(Map<String, String> data) {
        expiration = Integer.parseInt(data.get(EXPIRATION_NOTE));
        status = data.get(STATUS_NOTE);
    }

    public static final DecoupledAuthnResult deserializeCode(Map<String, String> data) {
        return new DecoupledAuthnResult(data);
    }

    public Map<String, String> serializeCode() {
        Map<String, String> result = new HashMap<>();
        result.put(EXPIRATION_NOTE, String.valueOf(expiration));
        result.put(STATUS_NOTE, status);
        return result;
    }

    public int getExpiration() {
        return expiration;
    }

    public String getStatus() {
        return status;
    }
}
