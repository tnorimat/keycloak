package org.keycloak.protocol.oidc.rar;

import javax.ws.rs.core.MultivaluedMap;
import java.util.List;

public class DefaultRichAuthzRequestProvider implements RichAuthzRequestProvider{
    @Override
    public void close() {

    }

    @Override
    public void checkAuthorizationDetails(String authorizationDetailsJson, List authorizationDetailsTypes) throws Exception {
        return;
    }

    @Override
    public List<String> getAuthorizationDetailsTypesSupported() {
        return null;
    }

    @Override
    public String enrichAuthorizationDetails(String authorizationDetailsJson, String grantManagementAction) {
        return authorizationDetailsJson;
    }

    @Override
    public String finaliseAuthorizationDetails(MultivaluedMap formData, String authorizationDetailsJson, String grantManagementAction) {
        return authorizationDetailsJson;
    }
}
