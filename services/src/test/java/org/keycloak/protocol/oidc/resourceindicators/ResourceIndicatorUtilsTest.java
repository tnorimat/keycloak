package org.keycloak.protocol.oidc.resourceindicators;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class ResourceIndicatorUtilsTest {

    @Test
    public void testJoinAndSplit() {
        Assert.assertNull(ResourceIndicatorUtils.join(null));
        Assert.assertNull(ResourceIndicatorUtils.join(List.of()));
        Assert.assertEquals("https://a urn:client:b", ResourceIndicatorUtils.join(List.of("https://a", "urn:client:b")));

        Assert.assertEquals(List.of(), ResourceIndicatorUtils.split(null));
        Assert.assertEquals(List.of(), ResourceIndicatorUtils.split(" "));
        Assert.assertEquals(List.of("https://a"), ResourceIndicatorUtils.split("https://a"));
        Assert.assertEquals(List.of("https://a", "urn:client:b"), ResourceIndicatorUtils.split("https://a  urn:client:b"));
    }

    @Test
    public void testClaimConversion() {
        Assert.assertNull(ResourceIndicatorUtils.toClaim(List.of()));
        Assert.assertEquals("https://a", ResourceIndicatorUtils.toClaim(List.of("https://a")));
        Assert.assertEquals(List.of("https://a", "https://b"), ResourceIndicatorUtils.toClaim(List.of("https://a", "https://b")));

        Assert.assertEquals(List.of(), ResourceIndicatorUtils.fromClaim(null));
        Assert.assertEquals(List.of("https://a"), ResourceIndicatorUtils.fromClaim("https://a"));
        Assert.assertEquals(List.of("https://a", "https://b"), ResourceIndicatorUtils.fromClaim(List.of("https://a", "https://b")));
    }

}
