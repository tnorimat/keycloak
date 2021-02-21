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
package org.keycloak.models;

import java.io.Serializable;

public class CIBAPolicy implements Serializable {

    private String cibaFlow;
    private String backchannelTokenDeliveryMode = "poll";
    private int expiresIn = 120;
    private int interval = 0;
    private String authRequestedUserHint = "login_hint";

    public String getCibaFlow() {
        return cibaFlow;
    }

    public void setCibaFlow(String cibaFlow) {
        this.cibaFlow = cibaFlow;
    }

    public String getBackchannelTokenDeliveryMode() {
        return backchannelTokenDeliveryMode;
    }

    public void setBackchannelTokenDeliveryMode(String backchannelTokenDeliveryMode) {
        this.backchannelTokenDeliveryMode = backchannelTokenDeliveryMode;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public int getInterval() {
        return interval;
    }

    public void setInterval(int interval) {
        this.interval = interval;
    }

    public String getAuthRequestedUserHint() {
        return authRequestedUserHint;
    }

    public void setAuthRequestedUserHint(String authRequestedUserHint) {
        this.authRequestedUserHint = authRequestedUserHint;
    }
}
