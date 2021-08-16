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
package org.keycloak.protocol.oidc.rar;

import org.keycloak.provider.Provider;
import javax.ws.rs.core.MultivaluedMap;
import java.util.List;

public interface RichAuthzRequestProvider<T> extends Provider {

    /**
     * This method do several check such as:
     * syntax check, if the authorizationDetails Json Object is valid
     * conforming to the respective types definition supported
     * check the required field
     *
     * @param authorizationDetailsJson authorization details
     * @param authorizationDetailsTypes client authorization detail type supported
     */
   void checkAuthorizationDetails(String authorizationDetailsJson, List<String> authorizationDetailsTypes) throws Exception;

    /**
     *
     * @return a list of AuthorizationDetails data types supported
     */
   List<String> getAuthorizationDetailsTypesSupported();

    /**
     * This method will enriches AuthorizationDetails with some data if needed
     * and return an Object which will be show to the user in the grant page.
     *
     * It can be the case where Client sent an authorization details with some empty field that should be fill.
     *
     * @param grantManagementAction action to be done (create, replace, update)
     * @param authorizationDetailsJson
     * @return T
     */
   T enrichAuthorizationDetails(String authorizationDetailsJson, String grantManagementAction);

    /**
     * This method check and return authorizationDetails in a final structure which will be save in a grant.
     *
     * @param grantManagementAction action to be done (create, replace, update)
     * @param formData
     * @param authorizationDetailsJson
     * @return a authorizationDetails
     */
   String finaliseAuthorizationDetails(MultivaluedMap<String, String> formData, String authorizationDetailsJson, String grantManagementAction);
}
