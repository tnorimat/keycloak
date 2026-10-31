package org.keycloak.protocol.oidc.resourceindicators;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Helpers for (de)serializing multiple {@code resource} parameter values (RFC 8707).
 * <p>
 * Resource indicators are absolute URIs, which cannot contain whitespace, so a space-delimited string is used where
 * only a single string can be stored (for example client notes or authorization code data). Values must be validated
 * with {@link ResourceIndicatorValidation#isValidResourceIndicator(String)} before they are joined.
 */
public final class ResourceIndicatorUtils {

    private static final String DELIMITER = " ";

    private ResourceIndicatorUtils() {
    }

    public static String join(Collection<String> resources) {
        if (resources == null || resources.isEmpty()) {
            return null;
        }
        return String.join(DELIMITER, resources);
    }

    public static List<String> split(String resources) {
        if (resources == null || resources.isBlank()) {
            return List.of();
        }
        return Arrays.stream(resources.trim().split(DELIMITER + "+")).toList();
    }

    /**
     * Converts the {@code resource} claim of a refresh token into a list. The claim is a string when a single resource
     * was requested and an array when multiple resources were requested.
     */
    public static List<String> fromClaim(Object claim) {
        if (claim == null) {
            return List.of();
        }
        if (claim instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).toList();
        }
        return List.of(claim.toString());
    }

    /**
     * Inverse of {@link #fromClaim(Object)}. A single resource is stored as a string for backward compatibility.
     */
    public static Object toClaim(List<String> resources) {
        if (resources == null || resources.isEmpty()) {
            return null;
        }
        return resources.size() == 1 ? resources.get(0) : List.copyOf(resources);
    }

}
