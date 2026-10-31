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

package org.keycloak.testframework.conformance;

import java.net.URI;
import java.time.Duration;

import org.keycloak.testframework.config.Config;
import org.keycloak.testframework.logging.JBossContainerLogConsumer;
import org.keycloak.testframework.util.ContainerImages;

import org.jboss.logging.Logger;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * An optional reverse proxy in front of Keycloak, so the conformance suite reaches Keycloak through it. It adds what
 * FAPI requires of resource server responses but Keycloak's userinfo endpoint, used as the resource endpoint, does not
 * send: the Date and x-fapi-interaction-id headers. A deployment would typically have an API gateway or the resource
 * server itself provide them. Keycloak still processes every request; its {@code hostname} has to be
 * {@link #BASE_URI}, so DPoP proofs created for the proxy's address are valid, and it reads the TLS client
 * certificate for certificate bound access tokens from the {@link #CLIENT_CERTIFICATE_HEADER} header.
 *
 * The proxy is disabled by default, so the tests exercise Keycloak as is; enable it with the
 * {@value #ENABLED_PROPERTY} test framework option (system property, {@code KC_TEST_CONFORMANCE_PROXY} environment
 * variable or keycloak-test.properties).
 */
public final class KeycloakProxy implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(KeycloakProxy.class);

    public static final String ENABLED_PROPERTY = "kc.test.conformance.proxy";

    // The proxy's address within the container network, i.e. Keycloak's address for the suite and its browser
    public static final URI BASE_URI = URI.create("https://keycloak-proxy:8443");

    public static final String CLIENT_CERTIFICATE_HEADER = "ssl-client-cert";

    private static final String NGINX_CONFIG = "org/keycloak/testframework/conformance/keycloak-proxy-nginx.conf";

    private final GenericContainer<?> container;

    private KeycloakProxy(GenericContainer<?> container) {
        this.container = container;
    }

    public static boolean enabled() {
        return Config.get(ENABLED_PROPERTY, false, Boolean.class);
    }

    // Runs on the suite's network; it reuses the suite's nginx image, which comes with nginx and a TLS certificate
    static KeycloakProxy start(Network network) {
        LOGGER.info("Starting the reverse proxy in front of Keycloak for the conformance suite");
        GenericContainer<?> container = new GenericContainer<>(
                DockerImageName.parse(ContainerImages.getContainerImageName(OpenIdConformanceServer.NGINX_CONTAINER)))
                .withNetwork(network)
                .withNetworkAliases(BASE_URI.getHost())
                .withExposedPorts(BASE_URI.getPort())
                .withCopyFileToContainer(MountableFile.forClasspathResource(NGINX_CONFIG), "/etc/nginx/nginx.conf")
                .withLogConsumer(new JBossContainerLogConsumer(Logger.getLogger("managed.conformance.proxy")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(2)));
        container.start();
        return new KeycloakProxy(container);
    }

    @Override
    public void close() {
        container.stop();
    }
}
