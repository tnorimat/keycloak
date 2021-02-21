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

package org.keycloak.representations.idm;

public class CIBARepresentation {

    protected String cibaFlow;
    protected String cibaBackchannelTokenDeliveryMode;
    protected Integer cibaExpiresIn;
    protected Integer cibaInterval;
    protected String cibaAuthRequestedUserHint;

    public String getCibaFlow() {
        return cibaFlow;
    }

    public void setCibaFlow(String cibaFlow) {
        this.cibaFlow = cibaFlow;
    }

    public String getCibaBackchannelTokenDeliveryMode() {
        return cibaBackchannelTokenDeliveryMode;
    }

    public void setCibaBackchannelTokenDeliveryMode(String cibaBackchannelTokenDeliveryMode) {
        this.cibaBackchannelTokenDeliveryMode = cibaBackchannelTokenDeliveryMode;
    }

    public Integer getCibaExpiresIn() {
        return cibaExpiresIn;
    }

    public void setCibaExpiresIn(Integer cibaExpiresIn) {
        this.cibaExpiresIn = cibaExpiresIn;
    }

    public Integer getCibaInterval() {
        return cibaInterval;
    }

    public void setCibaInterval(Integer cibaInterval) {
        this.cibaInterval = cibaInterval;
    }

    public String getCibaAuthRequestedUserHint() {
        return cibaAuthRequestedUserHint;
    }

    public void setCibaAuthRequestedUserHint(String cibaAuthRequestedUserHint) {
        this.cibaAuthRequestedUserHint = cibaAuthRequestedUserHint;
    }

}
