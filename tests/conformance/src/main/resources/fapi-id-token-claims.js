// ID token claims for the FAPI conformance tests. The suite warns about claims in the ID token that the client did not
// request or that it does not know. Script mappers run after the attribute and property mappers.
//
// Keycloak always adds typ and sid to the ID token.
token.type(null);
token.setSessionId(null);

// The claims of the email scope, a default scope of the clients, which the suite does not request. The userinfo
// endpoint still returns them, e.g. when the suite requests them with the claims parameter. The email mappers put the
// claims in the other claims of the token, not in its email fields.
token.getOtherClaims().remove("email");
token.getOtherClaims().remove("email_verified");
