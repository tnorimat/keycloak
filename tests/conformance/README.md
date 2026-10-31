# Keycloak OpenID conformance tests

This module runs Keycloak against the official [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
to verify that Keycloak's OpenID for Verifiable Credentials, FAPI and OpenID Connect implementations conform to the
specifications. Each test drives a real conformance suite test module (plan creation, module execution and result
assertion) against a live Keycloak server, so a passing run is evidence of spec conformance, not just internal
correctness.

The conformance suite itself (its `mongodb`, `conformance` and `nginx` containers) is started automatically via
Testcontainers; the suite version is pinned by the `conformance.version` property in the root `pom.xml`
(currently `release-v5.3.0`). Keycloak is started by the test framework as a distribution server over HTTPS and
reached by the suite at `https://host.testcontainers.internal:8443`.

## What is covered

The tests are grouped into JUnit suites, one per profile/role, each with its own Keycloak server configuration. CI
runs every suite as a separate matrix job (`.github/workflows/conformance.yml`), so each suite gets its own JVM.
Running a single suite locally (see [Running the tests](#running-the-tests)) is equivalent.
Note that the combined `./mvnw package` invocation does **not** give per-suite process isolation: Surefire uses a
single reusable fork, so all suites run in the same JVM.

| Suite | Package | Role / profile | Client authentication |
|-------|---------|----------------|-----------------------|
| `Oid4VciHaipTestSuite` | `vci.haip` | OID4VCI issuer, **HAIP** (`oid4vci-1_0-issuer-haip-test-plan`) | client attestation + DPoP; includes the FAPI2 and mDoc modules |
| `Oid4VciNonHaipTestSuite` | `vci.nonhaip` | OID4VCI issuer, **non-HAIP** (`oid4vci-1_0-issuer-test-plan`, `fapi_profile=vci`) | `private_key_jwt` + DPoP |
| `Oid4VpTestSuite` | `vp` | OID4VP verifier (`oid4vp-1final-verifier-test-plan`) | wallet mock; plain and encrypted (`direct_post.jwt`) response modes |
| `Fapi2SecurityProfileTestSuite` | `fapi2` | OpenID provider, **FAPI 2.0 Security Profile** (`fapi2-security-profile-final-test-plan`, `plain_fapi`, `openid_connect`) | `private_key_jwt` + DPoP, PAR |
| `Fapi2MessageSigningTestSuite` | `fapi2sign` | OpenID provider, **FAPI 2.0 Message Signing** (`fapi2-message-signing-final-test-plan`, signed request objects, plain responses) | `private_key_jwt` + DPoP, PAR + JAR |
| `OidcTestSuite` | `oidc` | OpenID provider, **OpenID Connect Core** Config, Basic, Implicit and Hybrid certification plans | `client_secret_basic` / `client_secret_post`, static clients, discovery |
| `OidcLogoutTestSuite` | `oidclogout` | OpenID provider, **OpenID Connect logout**: RP-Initiated, Front-Channel and Back-Channel Logout and Session Management certification plans | `client_secret_basic`, static clients, discovery |

The suite/profile split is intentional: HAIP requires attestation-based client authentication, whereas the
conformance suite's issuer modules do not permit public or `client_secret` authentication, so the non-HAIP profile
uses `private_key_jwt`. Shared realm building blocks live in `vci/VciConformanceRealmUtil`; each profile's realm and
server configuration lives in `vci/haip` and `vci/nonhaip` respectively.

The FAPI realms enforce Keycloak's built-in `fapi-2-dpop-security-profile` and `fapi-2-dpop-message-signing` client
profiles on every client; the suite uses Keycloak's userinfo endpoint as the FAPI resource endpoint.

Each specification has its own package. Infrastructure the packages share, i.e. the conformance suite containers,
the suite API client and the scripted browser interactions, lives in the test framework's `conformance-runner`
module, and the OpenID provider tests share one Keycloak server configuration (`ConformanceServerConfig`).

For back-channel logout, Keycloak itself calls the suite. The suite publishes this endpoint on its
container-internal host, which Keycloak, running on the Docker host, cannot resolve, so the clients register it at
the suite's address on the Docker host, and the test server trusts the suite's self-signed TLS certificate without
hostname verification.

Modules are grouped by the browser interaction and the result they are expected to finish with. Besides `PASSED`,
a module may be expected to finish with `REVIEW` (Keycloak's error page or a second login is snapshotted for a
human reviewer), `SKIPPED` or `WARNING`; the reasons are documented next to the module lists.

Keycloak always adds the `typ` claim, and in FAPI also the `sid` claim, to the ID token, and puts the claims of a
requested scope, e.g. `email`, in it even when an access token is issued for the userinfo endpoint. The suite warns
about both, and no realm setting changes them, so this module packages script based protocol mappers
(`src/main/resources`, with the `scripts` feature enabled by `ConformanceServerConfig`) that the OpenID Connect and
FAPI 2.0 clients use: `oidc-id-token-claims.js` removes `typ` and, unless the response type is `id_token`, the email
claims, and `fapi-id-token-claims.js` removes `typ`, `sid` and the email claims the suite does not request. As Keycloak rejects an `id_token_hint` without `typ`,
the OpenID Connect logout realms do not use them. The OpenID Connect and FAPI 2.0 tests also disable the CSS
processing of the suite's browser (`browsercontrol_css_enable`), where most of their time used to go.

Known gaps, mostly of Keycloak:

- The session check of the Session Management plan does not complete, as Keycloak's `check_session_iframe` does not
  answer in the suite's HtmlUnit browser, so that module is disabled (`OidcSessionManagementRpInitiatedLogoutTest`).
- Keycloak does not send the `Date` header the suite requires on resource endpoint responses, and its userinfo
  endpoint accepts DPoP proofs signed with RS256. The FAPI modules that call the resource endpoint are therefore
  expected to finish with `FAILED`, but only on these known conditions (see `AbstractFapi2ConformanceTest`), so any
  other failure still fails the test. The optional reverse proxy (see [Running the tests](#running-the-tests)) adds
  the missing header.
- With FAPI 2.0 Message Signing, a PAR `request_uri` presented by a different client causes an internal server
  error, so that module is disabled (`Fapi2MessageSigningRequestUriForDifferentClientTest`).

## Prerequisites

- JDK and Maven (use the `./mvnw` wrapper).
- A running container runtime — **Docker or Podman** — with permission to pull from `registry.gitlab.com`.
- Keycloak built locally so the Quarkus distribution artifact is in your local Maven repository:

  ```bash
  ./mvnw install -DskipTests
  ```

## Running the tests

Run one suite (mirrors how CI runs them, one matrix job each):

```bash
./mvnw package -f tests/conformance/pom.xml -Dtest=Oid4VciNonHaipTestSuite
./mvnw package -f tests/conformance/pom.xml -Dtest=Oid4VciHaipTestSuite
./mvnw package -f tests/conformance/pom.xml -Dtest=Oid4VpTestSuite
./mvnw package -f tests/conformance/pom.xml -Dtest=Fapi2SecurityProfileTestSuite
./mvnw package -f tests/conformance/pom.xml -Dtest=Fapi2MessageSigningTestSuite
./mvnw package -f tests/conformance/pom.xml -Dtest=OidcTestSuite
./mvnw package -f tests/conformance/pom.xml -Dtest=OidcLogoutTestSuite
```

Run all suites together in one invocation (all suites share a single Surefire reusable fork, i.e. the same
JVM — this does not reproduce the per-process isolation of the CI matrix jobs):

```bash
./mvnw package -f tests/conformance/pom.xml
```

Run a single test class (fully qualified name; useful when iterating):

```bash
./mvnw test -f tests/conformance/pom.xml \
  -Dtest='org.keycloak.tests.conformance.vci.nonhaip.issuer.IssuerHappyFlowTest'
```

### Optional reverse proxy in front of Keycloak

FAPI requires resource server responses to carry the `Date` and `x-fapi-interaction-id` headers, which Keycloak's
userinfo endpoint, used as the resource endpoint, does not send. A deployment would typically have an API gateway or
the resource server itself provide them. To run the OpenID provider tests the way such a deployment works, enable the
reverse proxy of the conformance runner (`KeycloakProxy`) with the `kc.test.conformance.proxy` option, as a system
property, the `KC_TEST_CONFORMANCE_PROXY` environment variable or in `keycloak-test.properties`:

```bash
./mvnw package -f tests/conformance/pom.xml -Dtest=Fapi2SecurityProfileTestSuite -Dkc.test.conformance.proxy=true
```

The proxy, an nginx container on the suite's network, forwards every request to Keycloak, which still processes it,
and adds the two headers. The suite then reaches Keycloak at `https://keycloak-proxy:8443`, which the tests set as the
Keycloak `hostname`.
The modules expected to fail only because of the missing headers are then expected to pass; those failing on
Keycloak's own behaviour, e.g. accepting DPoP proofs signed with RS256, still fail. The proxy is disabled by default,
so the tests exercise Keycloak as is; the OID4VCI and OID4VP tests do not use it.

The first run pulls the conformance suite container images, so allow extra time. Full logs for a failed conformance
module are printed to the test output to aid debugging.
