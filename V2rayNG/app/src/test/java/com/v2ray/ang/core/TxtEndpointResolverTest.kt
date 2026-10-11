package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class TxtEndpointResolverTest {

    @Test
    fun parsesIpv4EndpointWithNonStandardPort() {
        assertEquals(
            TxtEndpointResolver.Endpoint("222.116.129.80", 12345),
            TxtEndpointResolver.parseEndpoint("222.116.129.80:12345"),
        )
    }

    @Test
    fun parsesQuotedIpv4AndBracketedIpv6Endpoints() {
        assertEquals(
            listOf(
                TxtEndpointResolver.Endpoint("222.111.210.67", 10000),
                TxtEndpointResolver.Endpoint("2001:db8::1", 8443),
            ),
            TxtEndpointResolver.parseEndpoints(
                listOf(
                    "\"222.111.210.67:10000\"",
                    "[2001:db8::1]:8443",
                    "222.111.210.67:10000",
                ),
            ),
        )
    }

    @Test
    fun rejectsDomainsMalformedAddressesAndInvalidPorts() {
        listOf(
            "edge.example.com:443",
            "222.111.210.999:443",
            "222.111.210.67:0",
            "222.111.210.67:65536",
            "2001:db8::1:443",
            "[2001:db8::1]",
            "not-an-endpoint",
        ).forEach { assertNull(TxtEndpointResolver.parseEndpoint(it), it) }
    }
}
