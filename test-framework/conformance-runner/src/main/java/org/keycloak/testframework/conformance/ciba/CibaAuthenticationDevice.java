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

package org.keycloak.testframework.conformance.ciba;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.keycloak.testframework.conformance.OpenIdConformanceServer;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.jboss.logging.Logger;
import org.testcontainers.Testcontainers;

/**
 * Emulates the authentication device (AD) of Keycloak's CIBA HTTP authentication channel, so the conformance suite
 * can approve or deny CIBA requests without a user.
 *
 * Keycloak posts each authentication request to {@link #authenticationChannelUri()} with a bearer token identifying
 * it. The suite then calls {@link #automatedApprovalUrl()} (its {@code automated_ciba_approval_url}) with the action
 * {@code allow} or {@code deny}, and the device completes the latest pending request at Keycloak's authentication
 * channel callback endpoint. The suite runs one module, and so one CIBA request, at a time, and Keycloak sends the
 * authentication request before answering the backchannel authentication request the suite approves, so the latest
 * pending request is the one to complete; older ones belong to modules that let their request expire.
 *
 * The device answers the suite right away and completes the request after the delay given in the approval URL. In
 * the ping mode, the suite polls the token endpoint just before it approves and requests the tokens as soon as the
 * ping notification arrives, and Keycloak answers slow_down to token requests within its polling interval, so the
 * callback has to wait longer than that interval.
 */
public final class CibaAuthenticationDevice {

    private static final Logger LOGGER = Logger.getLogger(CibaAuthenticationDevice.class);

    private static final String AUTHENTICATION_CHANNEL_PATH = "/ciba/authentication-channel";
    private static final String APPROVAL_PATH = "/ciba/approval";
    private static final String CALLBACK_PATH = "/protocol/openid-connect/ext/ciba/auth/callback";
    private static final String CALLBACK_DELAY_PARAM = "callback_delay_ms";

    private static final CibaAuthenticationDevice INSTANCE = start();

    private final HttpServer server;
    private final HttpClient httpClient;
    private final BlockingDeque<String> pendingRequests = new LinkedBlockingDeque<>();
    private final ScheduledExecutorService callbacks = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "ciba-authentication-device-callback");
        thread.setDaemon(true);
        return thread;
    });

    private CibaAuthenticationDevice(HttpServer server) {
        this.server = server;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .sslContext(trustAllSslContext())
                .build();
        server.createContext(AUTHENTICATION_CHANNEL_PATH, this::handleAuthenticationRequest);
        server.createContext(APPROVAL_PATH, this::handleApproval);
    }

    public static CibaAuthenticationDevice instance() {
        return INSTANCE;
    }

    private static CibaAuthenticationDevice start() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setExecutor(Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "ciba-authentication-device");
                thread.setDaemon(true);
                return thread;
            }));
            CibaAuthenticationDevice device = new CibaAuthenticationDevice(server);
            server.start();
            // the suite reaches the device on the Docker host, like it reaches Keycloak
            Testcontainers.exposeHostPorts(server.getAddress().getPort());
            Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
            return device;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to start the CIBA authentication device", e);
        }
    }

    // The URI of Keycloak's HTTP authentication channel, as Keycloak runs on the same host
    public String authenticationChannelUri() {
        return "http://localhost:" + server.getAddress().getPort() + AUTHENTICATION_CHANNEL_PATH;
    }

    // The automated_ciba_approval_url template the suite expands and calls from its container
    public String automatedApprovalUrl() {
        return automatedApprovalUrl(Duration.ZERO);
    }

    // The automated_ciba_approval_url template, completing the request the given delay after the approval
    public String automatedApprovalUrl(Duration callbackDelay) {
        return "http://host.testcontainers.internal:" + server.getAddress().getPort() + APPROVAL_PATH
                + "?auth_req_id={auth_req_id}&action={action}&" + CALLBACK_DELAY_PARAM + "=" + callbackDelay.toMillis();
    }

    private void handleAuthenticationRequest(HttpExchange exchange) throws IOException {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        exchange.getRequestBody().readAllBytes();
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            respond(exchange, 400, "{\"error\":\"missing bearer token\"}");
            return;
        }
        pendingRequests.addLast(authorization.substring("Bearer ".length()));
        // Keycloak only accepts 201 as the device having received the request
        respond(exchange, 201, "");
    }

    private void handleApproval(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
        String query = exchange.getRequestURI().getQuery();
        boolean allow = query != null && query.contains("action=allow");
        try {
            String token = pendingRequests.pollLast(10, TimeUnit.SECONDS);
            pendingRequests.clear();
            if (token == null) {
                respond(exchange, 409, "{\"error\":\"no pending CIBA authentication request\"}");
                return;
            }
            String status = allow ? "SUCCEED" : "UNAUTHORIZED";
            callbacks.schedule(() -> completeAuthenticationQuietly(token, status), callbackDelay(query), TimeUnit.MILLISECONDS);
            respond(exchange, 200, "{}");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            respond(exchange, 503, "{\"error\":\"interrupted\"}");
        }
    }

    // The user's action was delivered either way. A failing callback is left for the suite to judge from the token
    // endpoint, e.g. Keycloak failing the callback as the client notification endpoint rejects the ping. Log messages
    // are formatted upfront, as the test framework log filter replays buffered records without their parameters.
    private void completeAuthenticationQuietly(String token, String status) {
        try {
            HttpResponse<String> response = completeAuthentication(token, status);
            if (response.statusCode() / 100 != 2) {
                LOGGER.warn("Keycloak CIBA callback returned HTTP " + response.statusCode() + ": " + response.body());
            }
        } catch (IOException | RuntimeException e) {
            LOGGER.warn("Keycloak CIBA callback failed: " + e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static long callbackDelay(String query) {
        for (String parameter : query == null ? new String[0] : query.split("&")) {
            if (parameter.startsWith(CALLBACK_DELAY_PARAM + "=")) {
                return Long.parseLong(parameter.substring(CALLBACK_DELAY_PARAM.length() + 1));
            }
        }
        return 0;
    }

    private HttpResponse<String> completeAuthentication(String token, String status) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(callbackUri(token))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"status\":\"" + status + "\"}"))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // The callback of the token's realm, on localhost as the issuer host is only resolvable within the containers
    private static URI callbackUri(String token) throws IOException {
        String[] parts = token.split("\\.");
        JsonNode claims = JsonSerialization.readValue(Base64.getUrlDecoder().decode(parts[1]), JsonNode.class);
        String realmPath = URI.create(claims.path("iss").asText()).getRawPath();
        return URI.create("https://localhost:" + OpenIdConformanceServer.KEYCLOAK_BASE_URI.getPort() + realmPath + CALLBACK_PATH);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private static SSLContext trustAllSslContext() {
        try {
            TrustManager[] trustAll = {new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }
            }};
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustAll, new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create the CIBA authentication device SSL context", e);
        }
    }
}
