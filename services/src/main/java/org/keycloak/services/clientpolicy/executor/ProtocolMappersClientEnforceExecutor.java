package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

import java.util.List;
import java.util.Set;

public class ProtocolMappersClientEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ProtocolMappersClientEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ProtocolMappersClientEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
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
            case UPDATE:
                ClientUpdateContext registerClientContext = (ClientUpdateContext) context;
                checkProtocolMappers(registerClientContext.getProposedClientRepresentation());
                break;
            case REGISTERED:
                // Remove builtin mappers of unsupported types too
                ClientUpdateContext registeredClientContext = (ClientUpdateContext) context;
                ClientModel registeredClient = registeredClientContext.getRegisteredClient();

                // Remove mappers of unsupported type, which were added "automatically"
                List<String> allowedMapperProviders = getAllowedMapperProviders();
                Set<ProtocolMapperModel> createdMappers = registeredClient.getProtocolMappers();

                createdMappers.stream().filter(
                        (ProtocolMapperModel mapper) ->
                                !allowedMapperProviders.contains(mapper.getProtocolMapper())).forEach((ProtocolMapperModel mapperToRemove) -> {

                    logger.debugf("Removing builtin mapper '%s' of type '%s' as type is not permitted", mapperToRemove.getName(), mapperToRemove.getProtocolMapper());
                    registeredClient.removeProtocolMapper(mapperToRemove);

                });
                break;
            default:
                return;
        }
    }

    protected void checkProtocolMappers(ClientRepresentation clientRepresentation) throws ClientPolicyException {
        List<ProtocolMapperRepresentation> protocolMappers = clientRepresentation.getProtocolMappers();
        if (protocolMappers == null) {
            return;
        }

        List<String> allowedMapperProviders = getAllowedMapperProviders();

        for (ProtocolMapperRepresentation mapper : protocolMappers) {
            String mapperType = mapper.getProtocolMapper();

            if (!allowedMapperProviders.contains(mapperType)) {
                ServicesLogger.LOGGER.clientRegistrationMapperNotAllowed(mapper.getName(), mapperType);
                throw new ClientPolicyException(Errors.NOT_ALLOWED, "ProtocolMapper type not allowed");
            }
        }
    }

    private List<String> getAllowedMapperProviders() {
        return componentModel.getConfig().getList(ProtocolMappersClientEnforceExecutorFactory.ALLOWED_PROTOCOL_MAPPER_TYPES);
    }
}
