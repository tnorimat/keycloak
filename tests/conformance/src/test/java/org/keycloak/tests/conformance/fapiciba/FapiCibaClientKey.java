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

package org.keycloak.tests.conformance.fapiciba;

import org.keycloak.tests.conformance.ConformanceSigningKey;

import org.bouncycastle.asn1.x509.KeyPurposeId;

import static org.keycloak.tests.conformance.fapiciba.FapiCibaRealmConfig.REALM;

/**
 * The keys of the two FAPI-CIBA conformance clients, generated at runtime so no private key material is committed to
 * the repository. Each key signs the client's assertions and request objects, and its CA-issued certificate is the
 * client's TLS certificate, as FAPI-CIBA requires certificate bound access tokens. Keycloak trusts the CAs of both
 * certificates for TLS client authentication.
 */
public final class FapiCibaClientKey {

    public static final ConformanceSigningKey CLIENT = ConformanceSigningKey.generate(
            REALM, "fapi_ciba_client_key", "FAPI-CIBA Conformance Client", KeyPurposeId.id_kp_clientAuth);

    public static final ConformanceSigningKey CLIENT2 = ConformanceSigningKey.generate(
            REALM, "fapi_ciba_client2_key", "FAPI-CIBA Conformance Client 2", KeyPurposeId.id_kp_clientAuth);

    private FapiCibaClientKey() {
    }
}
