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

package org.keycloak.services.clientpolicy;

public class ClientPolicyException extends Exception {
    private String error;
    private String error_detail;

    public ClientPolicyException(String message) {
        super(message);
    }

    public ClientPolicyException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public ClientPolicyException(String error, String error_detail) {
        super(error);
        setError(error);
        setErrorDetail(error_detail);
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDetail() {
        return error_detail;
    }

    public void setErrorDetail(String error_detail) {
        this.error_detail = error_detail;
    }


}
