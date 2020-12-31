package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.*;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ClientScopesClientRegistrationEnforcerExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ClientScopesClientRegistrationEnforcerExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientScopesClientRegistrationEnforcerExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case REGISTER:
                executeOnRegister(context);
                break;
            case UPDATE:
                executeOnUpdate(context);
                break;
            default:
                return;
        }
    }

    private void executeOnRegister(ClientPolicyContext context) throws ClientPolicyException {
        ClientRepresentation clientRepresentation;
        if (context instanceof AdminClientRegisterContext) {
            clientRepresentation = ((AdminClientRegisterContext) context).getProposedClientRepresentation();
        } else if (context instanceof DynamicClientRegisterContext) {
            clientRepresentation = ((DynamicClientRegisterContext) context).getProposedClientRepresentation();
        } else {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed input format.");
        }

        List<String> requestedDefaultScopeNames = clientRepresentation.getDefaultClientScopes();
        List<String> requestedOptionalScopeNames = clientRepresentation.getOptionalClientScopes();

        RealmModel realm = session.getContext().getRealm();
        List<String> allowedDefaultScopeNames = getAllowedScopeNames(realm, true);
        List<String> allowedOptionalScopeNames = getAllowedScopeNames(realm, false);

        checkClientScopesAllowed(requestedDefaultScopeNames, allowedDefaultScopeNames);
        checkClientScopesAllowed(requestedOptionalScopeNames, allowedOptionalScopeNames);
    }

    private void executeOnUpdate(ClientPolicyContext context) throws ClientPolicyException {
        ClientRepresentation clientRepresentation;
        if (context instanceof AdminClientUpdateContext) {
            clientRepresentation = ((AdminClientUpdateContext) context).getProposedClientRepresentation();
        } else if (context instanceof DynamicClientUpdateContext) {
            clientRepresentation = ((DynamicClientUpdateContext) context).getProposedClientRepresentation();
        } else {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed input format.");
        }

        List<String> requestedDefaultScopeNames = clientRepresentation.getDefaultClientScopes();
        List<String> requestedOptionalScopeNames = clientRepresentation.getOptionalClientScopes();

        ClientModel clientModel;
        if (context instanceof AdminClientUpdateContext) {
            clientModel = ((AdminClientUpdateContext) context).getClientToBeUpdated();
        } else if (context instanceof DynamicClientUpdateContext) {
            clientModel = ((DynamicClientUpdateContext) context).getClientToBeUpdated();
        } else {
            throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "not allowed input format.");
        }
        // Allow scopes, which were already presented before
        if (requestedDefaultScopeNames != null) {
            requestedDefaultScopeNames.removeAll(clientModel.getClientScopes(true, false).keySet());
        }
        if (requestedOptionalScopeNames != null) {
            requestedOptionalScopeNames.removeAll(clientModel.getClientScopes(false, false).keySet());
        }

        RealmModel realm = session.getContext().getRealm();
        List<String> allowedDefaultScopeNames = getAllowedScopeNames(realm, true);
        List<String> allowedOptionalScopeNames = getAllowedScopeNames(realm, false);

        checkClientScopesAllowed(requestedDefaultScopeNames, allowedDefaultScopeNames);
        checkClientScopesAllowed(requestedOptionalScopeNames, allowedOptionalScopeNames);
    }

    private void checkClientScopesAllowed(List<String> requestedScopes, List<String> allowedScopes) throws ClientPolicyException {
        if (requestedScopes != null) {
            for (String requested : requestedScopes) {
                if (!allowedScopes.contains(requested)) {
                    logger.warnf("Requested scope '%s' not trusted in the list: %s", requested, allowedScopes.toString());
                    throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Not permitted to use specified clientScope");
                }
            }
        }
    }

    private List<String> getAllowedScopeNames(RealmModel realm, boolean defaultScopes) {
        List<String> allAllowed = new LinkedList<>();

        // Add client scopes allowed by config
        List<String> allowedScopesConfig = componentModel.getConfig().getList(ClientScopesClientRegistrationEnforcerExecutorFactory.ALLOWED_CLIENT_SCOPES);
        if (allowedScopesConfig != null) {
            allAllowed.addAll(allowedScopesConfig);
        }

        // If allowDefaultScopes, then realm default scopes are allowed as default scopes (+ optional scopes are allowed as optional scopes)
        boolean allowDefaultScopes = componentModel.get(ClientScopesClientRegistrationEnforcerExecutorFactory.ALLOW_DEFAULT_SCOPES, true);
        if (allowDefaultScopes) {
            List<String> scopeNames = realm.getDefaultClientScopes(defaultScopes).stream()
                                              .map(ClientScopeModel::getName)
                                              .collect(Collectors.toList());

            allAllowed.addAll(scopeNames);
        }

        return allAllowed;
    }
}
