package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
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
    fun unwrapsQuotedTxtPayloads() {
        assertEquals(
            "222.111.210.67:10000",
            TxtEndpointResolver.unwrapTxtPayload("\"222.111.210.67:10000\""),
        )
        assertEquals(
            "222.116.129.80:12345",
            TxtEndpointResolver.formatEndpoint(TxtEndpointResolver.Endpoint("222.116.129.80", 12345)),
        )
        assertEquals(
            "[2001:db8::1]:8443",
            TxtEndpointResolver.formatEndpoint(TxtEndpointResolver.Endpoint("2001:db8::1", 8443)),
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

    @Test
    fun parsesUdpTxtResponseWithCnameAndNonStandardPorts() {
        val packet = hexToBytes(
            "123481800001000400000000026b72063237303337360378797a0000100001c00c000500010000003c0012056b72747874063237303337360378797a00c02b001000010000003b0015143232322e3131362e3132392e38303a3132333435c02b001000010000003b0015143232322e3131312e3231302e36373a3130303030c02b001000010000003b0016153232322e3130382e3234332e3139343a3130303030",
        )
        val (records, ttl) = TxtEndpointResolver.parseDnsTxtResponse(packet)
        assertEquals(
            listOf(
                "222.116.129.80:12345",
                "222.111.210.67:10000",
                "222.108.243.194:10000",
            ),
            records,
        )
        assertTrue(ttl in 1..60)
        assertEquals(60_000L, TxtEndpointResolver.cacheTtlMs(60))
        assertEquals(0L, TxtEndpointResolver.cacheTtlMs(0))
        val endpoint = TxtEndpointResolver.Endpoint("222.116.129.80", 12345)
        val record = TxtEndpointResolver.formatCachedRecord(endpoint, 1_700_000_060_000L)
        assertEquals(
            endpoint,
            TxtEndpointResolver.parseCachedRecord(record, 1_700_000_000_000L),
        )
        assertNull(TxtEndpointResolver.parseCachedRecord(record, 1_700_000_060_000L))
        assertNull(TxtEndpointResolver.parseCachedRecord("222.116.129.80:12345", 1L))
        assertEquals(
            emptyList<TxtEndpointResolver.Endpoint>(),
            TxtEndpointResolver.parseEndpoints(listOf("v=spf1 -all", "google-site-verification=abc")),
        )
        assertEquals(
            setOf(
                TxtEndpointResolver.Endpoint("222.116.129.80", 12345),
                TxtEndpointResolver.Endpoint("222.111.210.67", 10000),
                TxtEndpointResolver.Endpoint("222.108.243.194", 10000),
            ),
            TxtEndpointResolver.parseEndpoints(records).toSet(),
        )
        assertTrue(TxtEndpointResolver.prefersTxt("kr.270376.xyz"))
        assertFalse(TxtEndpointResolver.prefersTxt("222.116.129.80"))
        assertFalse(TxtEndpointResolver.prefersTxt("2001:db8::1"))
        assertFalse(TxtEndpointResolver.prefersTxt("[2001:db8::1]"))
        assertFalse(TxtEndpointResolver.prefersTxt(""))
    }

    private fun hexToBytes(hex: String): ByteArray {
        val data = ByteArray(hex.length / 2)
        for (index in data.indices) {
            data[index] = hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
        return data
    }
}
