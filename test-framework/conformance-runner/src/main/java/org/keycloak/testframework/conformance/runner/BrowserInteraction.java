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

package org.keycloak.testframework.conformance.runner;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.testframework.conformance.runner.BrowserFlow.BrowserTask;

public interface BrowserInteraction {

    BrowserInteraction NONE = new None();
    BrowserInteraction LOGIN = new Login();
    BrowserInteraction DENY_CONSENT = new DenyConsent();
    BrowserInteraction LOGIN_ON_SECOND_VISIT = new LoginOnSecondVisit();
    BrowserInteraction ERROR_CALLBACK = new ErrorCallback();
    BrowserInteraction LOGIN_WITH_SCREENSHOT_ON_SECOND_LOGIN = new LoginWithScreenshotOnSecondLogin();
    BrowserInteraction LOGOUT = new Logout();
    BrowserInteraction LOGOUT_PAGE_SCREENSHOT = new LogoutPageScreenshot();
    BrowserInteraction CONFIRM_LOGOUT_WITH_SCREENSHOT = new ConfirmLogoutWithScreenshot();
    BrowserInteraction SESSION_MANAGEMENT_LOGOUT = new SessionManagementLogout();

    /**
     * Asserts Keycloak renders its error page with a message matching {@code messageRegexp} at the authorization
     * endpoint (no login).
     */
    static BrowserInteraction errorPage(String messageRegexp) {
        return new ErrorPage(messageRegexp);
    }

    /**
     * Logs in and completes the first authorization, then asserts the second authorization is rejected with
     * Keycloak's error page matching {@code messageRegexp}.
     */
    static BrowserInteraction loginThenErrorPageOnSecondVisit(String messageRegexp) {
        return new LoginThenErrorPageOnSecondVisit(messageRegexp);
    }

    List<BrowserFlow> browserFlows(BrowserContext context);

    record BrowserContext(String realm, String username, String password, String callbackUrl) {

        String authorizationEndpoint() {
            return "https://*/realms/" + realm + "/protocol/openid-connect/auth*";
        }

        // Keycloak renders the login form on the authorization endpoint for a plain authorization request, and under
        // login-actions once the flow has been restarted (e.g. after resolving a PAR request_uri), so match both
        String loginPage() {
            return "https://*/realms/" + realm + "/*";
        }

        String endSessionEndpoint() {
            return "https://*/realms/" + realm + "/protocol/openid-connect/logout*";
        }

        // The suite's post_logout_redirect_uri, which replaces callback in the redirect_uri
        String postLogoutRedirectUri() {
            return callbackUrl.replaceFirst("/callback$", "/post_logout_redirect");
        }
    }

    /**
     * The login flows of {@link Login} followed by the given logout flow. The first authorization requires a login,
     * later ones (e.g. the prompt=none request after a logout) may skip it.
     */
    private static List<BrowserFlow> withLoginFlows(BrowserContext context, BrowserFlow logoutFlow) {
        List<BrowserFlow> flows = new ArrayList<>(LOGIN.browserFlows(context));
        flows.add(logoutFlow);
        return flows;
    }

    // command, element selector type, element selector, timeout in seconds, element text regexp, action
    private static List<Object> screenshotCommand(String elementId) {
        return List.of(BrowserTask.WAIT, "id", elementId, 10, ".*", BrowserTask.UPDATE_IMAGE_PLACEHOLDER);
    }

    private static BrowserTask loginTask(BrowserContext context, boolean optional) {
        return new BrowserTask(
                "Keycloak Login",
                context.loginPage(),
                optional,
                List.of(
                        // command, element selector type, element selector, value to enter
                        List.of(BrowserTask.TEXT, "id", "username", context.username()),
                        List.of(BrowserTask.TEXT, "id", "password", context.password()),
                        // command, element selector type, element selector
                        List.of(BrowserTask.CLICK, "id", "kc-login")));
    }

    private static BrowserTask verifyCompleteTask(BrowserContext context) {
        return new BrowserTask(
                "Verify Complete",
                context.callbackUrl() + "*",
                // command, element selector type, element selector, timeout in seconds
                List.of(List.of(BrowserTask.WAIT, "id", "submission_complete", 10)));
    }

    private static BrowserTask errorPageTask(BrowserContext context, String messageRegexp) {
        return new BrowserTask(
                "Keycloak Error Page",
                context.authorizationEndpoint(),
                // command, element selector type, element selector, timeout in seconds, element text regexp, action
                List.of(List.of(BrowserTask.WAIT, "id", "kc-error-message", 10, messageRegexp,
                        BrowserTask.UPDATE_IMAGE_PLACEHOLDER)));
    }

    record None() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            return List.of();
        }
    }

    /**
     * Requires a login on the first authorization visit. Later visits reuse the SSO session, where Keycloak may
     * skip the login page, so the login task is optional there.
     */
    record Login() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            BrowserFlow firstVisit = new BrowserFlow(context.authorizationEndpoint(), 1, List.of(
                    loginTask(context, false),
                    verifyCompleteTask(context)));
            BrowserFlow laterVisits = new BrowserFlow(context.authorizationEndpoint(), List.of(
                    loginTask(context, true),
                    verifyCompleteTask(context)));
            return List.of(firstVisit, laterVisits);
        }
    }

    record DenyConsent() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            return List.of(new BrowserFlow(context.authorizationEndpoint(), List.of(
                    // optional so a second authorization that reuses the SSO session skips the login
                    loginTask(context, true),
                    new BrowserFlow.BrowserTask(
                            "Deny Consent",
                            // the consent (oauth grant) screen is served under login-actions during the auth flow,
                            // optional so a second authorization that goes straight to the callback is tolerated
                            "https://*/realms/" + context.realm() + "/login-actions/*",
                            true,
                            List.of(
                                    // wait for the deny button, then click it to reject the grant
                                    List.of(BrowserTask.WAIT, "id", "kc-cancel", 10),
                                    List.of(BrowserTask.CLICK, "id", "kc-cancel"))),
                    // the suite renders submission_complete on the callback for the access_denied response too
                    verifyCompleteTask(context))));
        }
    }

    /**
     * Completes a normal login on the first authorization visit, then requires Keycloak's error page (matching
     * {@code messageRegexp}) on the second visit. The first flow uses match-limit 1 so it applies only once; the
     * second flow handles every later visit.
     */
    record LoginThenErrorPageOnSecondVisit(String messageRegexp) implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            BrowserFlow firstVisit = new BrowserFlow(context.authorizationEndpoint(), 1, List.of(
                    loginTask(context, false),
                    verifyCompleteTask(context)));
            BrowserFlow secondVisit = new BrowserFlow(context.authorizationEndpoint(), List.of(
                    errorPageTask(context, messageRegexp)));
            return List.of(firstVisit, secondVisit);
        }
    }

    /**
     * Loads the login page on the first authorization visit without authenticating, then logs in on the second
     * visit. The first flow uses match-limit 1 so it applies only once, the second flow handles every later
     * visit. This keeps the first authorization incomplete so a request_uri stays valid for the second visit.
     */
    record LoginOnSecondVisit() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            BrowserFlow firstVisit = new BrowserFlow(context.authorizationEndpoint(), 1, List.of(
                    new BrowserFlow.BrowserTask(
                            "Load login page without authenticating",
                            context.loginPage(),
                            // wait for the form to confirm the request_uri was accepted, but do not submit it
                            List.of(List.of(BrowserTask.WAIT, "id", "username", 10)))));
            BrowserFlow secondVisit = new BrowserFlow(context.authorizationEndpoint(), List.of(
                    loginTask(context, false),
                    verifyCompleteTask(context)));
            return List.of(firstVisit, secondVisit);
        }
    }

    /**
     * Logs in on the first authorization visit, then requires the login page again on the second visit (e.g.
     * prompt=login or max_age=1) and snapshots it into the screenshot placeholder before logging in, as the module
     * waits for that screenshot. The first flow uses match-limit 1 so it applies only once.
     */
    record LoginWithScreenshotOnSecondLogin() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            BrowserFlow firstVisit = new BrowserFlow(context.authorizationEndpoint(), 1, List.of(
                    loginTask(context, false),
                    verifyCompleteTask(context)));
            BrowserFlow secondVisit = new BrowserFlow(context.authorizationEndpoint(), List.of(
                    new BrowserTask(
                            "Keycloak Second Login",
                            context.loginPage(),
                            List.of(
                                    // command, element selector type, element selector, timeout in seconds,
                                    // element text regexp, action
                                    List.of(BrowserTask.WAIT, "id", "kc-page-title", 10, ".*",
                                            BrowserTask.UPDATE_IMAGE_PLACEHOLDER),
                                    // the re-authentication form only asks for the password, as the user is known
                                    List.of(BrowserTask.TEXT, "id", "username", context.username(), "optional"),
                                    List.of(BrowserTask.TEXT, "id", "password", context.password()),
                                    List.of(BrowserTask.CLICK, "id", "kc-login"))),
                    verifyCompleteTask(context)));
            return List.of(firstVisit, secondVisit);
        }
    }

    /**
     * Logs in, then follows the RP-initiated logout at the end_session_endpoint back to the post_logout_redirect_uri.
     * Keycloak redirects straight away, except with front-channel logout, where its logout page first loads the
     * clients' frontchannel_logout_uri in iframes and then redirects by script. The task waiting on that page is
     * optional, so it is skipped when Keycloak redirects straight away.
     */
    record Logout() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            return withLoginFlows(context, new BrowserFlow(context.endSessionEndpoint(), List.of(
                    new BrowserTask(
                            "Wait for Front-Channel Logout",
                            context.endSessionEndpoint(),
                            true,
                            // the wait keeps polling across the scripted redirect to the post_logout_redirect_uri
                            List.of(List.of(BrowserTask.WAIT, "id", "complete", 30))),
                    new BrowserTask(
                            "Verify Post Logout Redirect",
                            context.postLogoutRedirectUri() + "*",
                            List.of(List.of(BrowserTask.WAIT, "id", "complete", 10))))));
        }
    }

    /**
     * Like {@link Logout}, and additionally loads the suite's session check pages before and after the logout. The
     * suite only drives its browser to URLs a flow matches, so without this flow the checks never run. Each page
     * compares the session state through Keycloak's check_session_iframe, then sends the browser to the suite's
     * result page; the wait keeps polling across that scripted navigation.
     */
    record SessionManagementLogout() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            // matches both session_verify (before the logout) and second_session_verify (after it)
            String sessionVerifyPage = context.callbackUrl().replaceFirst("/callback$", "/*session_verify*");
            List<BrowserFlow> flows = new ArrayList<>(LOGOUT.browserFlows(context));
            flows.add(new BrowserFlow(sessionVerifyPage, List.of(
                    new BrowserTask(
                            "Verify Session State",
                            sessionVerifyPage,
                            List.of(List.of(BrowserTask.WAIT, "id", "complete", 30))))));
            return flows;
        }
    }

    /**
     * Logs in, then snapshots the page Keycloak renders at the end_session_endpoint, i.e. its error page or its logout
     * confirmation, for the modules that require the OP to not redirect back.
     */
    record LogoutPageScreenshot() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            return withLoginFlows(context, new BrowserFlow(context.endSessionEndpoint(), List.of(
                    new BrowserTask(
                            "Keycloak Logout Page",
                            context.endSessionEndpoint(),
                            List.of(screenshotCommand("kc-page-title"))))));
        }
    }

    /**
     * Logs in, then confirms the logout if Keycloak asks for it (without an id_token_hint) and snapshots Keycloak's
     * "you are logged out" page, for the modules without a post_logout_redirect_uri.
     */
    record ConfirmLogoutWithScreenshot() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            return withLoginFlows(context, new BrowserFlow(context.endSessionEndpoint(), List.of(
                    new BrowserTask(
                            "Confirm Logout",
                            context.endSessionEndpoint(),
                            // command, element selector type, element selector, skip when the element is missing
                            List.of(List.of(BrowserTask.CLICK, "id", "kc-logout", "optional"))),
                    new BrowserTask(
                            "Keycloak Logged Out Page",
                            context.endSessionEndpoint(),
                            List.of(screenshotCommand("kc-info-message"))))));
        }
    }

    record ErrorPage(String messageRegexp) implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            return List.of(new BrowserFlow(context.authorizationEndpoint(), List.of(
                    errorPageTask(context, messageRegexp))));
        }
    }

    /**
     * Asserts Keycloak rejects the authorization request without any login by redirecting the error response
     * straight to the callback, where the module validates it.
     */
    record ErrorCallback() implements BrowserInteraction {

        @Override
        public List<BrowserFlow> browserFlows(BrowserContext context) {
            return List.of(new BrowserFlow(context.authorizationEndpoint(), List.of(
                    verifyCompleteTask(context))));
        }
    }
}
