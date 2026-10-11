package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetAddress
import java.net.UnknownHostException
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/** Resolves strict IP:port TXT records only when a host has no ordinary A/AAAA address. */
object TxtEndpointResolver {
    data class Endpoint(val address: String, val port: Int)

    private const val QUERY_TIMEOUT_SECONDS = 4L
    private const val TXT_RECORD_TYPE = 16
    private val random = SecureRandom()
    private val client = OkHttpClient.Builder()
        .connectTimeout(QUERY_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(QUERY_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .build()
    private val resolvers = listOf(
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
    )

    /**
     * Returns a TXT endpoint only when [host] cannot be resolved conventionally.
     * This keeps existing profiles unchanged and makes TXT discovery an automatic fallback.
     */
    fun resolveWhenAddressMissing(host: String): Endpoint? {
        val normalizedHost = host.trim().removeSuffix(".")
        if (normalizedHost.isEmpty() || isIpLiteral(normalizedHost)) return null

        try {
            if (InetAddress.getAllByName(normalizedHost).isNotEmpty()) return null
        } catch (_: UnknownHostException) {
            // A/AAAA is intentionally absent for TXT-discovered endpoints.
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "TXT endpoint: failed conventional lookup for host", e)
            return null
        }

        for (resolver in resolvers) {
            try {
                val records = queryTxt(resolver, normalizedHost)
                val endpoints = parseEndpoints(records)
                if (endpoints.isNotEmpty()) {
                    val endpoint = endpoints[random.nextInt(endpoints.size)]
                    LogUtil.i(AppConfig.TAG, "TXT endpoint: resolved $normalizedHost to ${endpoint.address}:${endpoint.port}")
                    return endpoint
                }
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "TXT endpoint: resolver request failed for host", e)
            }
        }
        return null
    }

    internal fun parseEndpoints(records: List<String>): List<Endpoint> =
        records.mapNotNull(::parseEndpoint).distinct()

    internal fun parseEndpoint(record: String): Endpoint? {
        val value = record.trim().removeSurrounding("\"").trim()
        val address: String
        val portText: String

        if (value.startsWith("[")) {
            val closingBracket = value.indexOf(']')
            if (closingBracket <= 1 || closingBracket + 1 >= value.length || value[closingBracket + 1] != ':') return null
            address = value.substring(1, closingBracket)
            portText = value.substring(closingBracket + 2)
            if (!isIpv6Literal(address)) return null
        } else {
            val separator = value.lastIndexOf(':')
            if (separator <= 0 || value.indexOf(':') != separator) return null
            address = value.substring(0, separator)
            portText = value.substring(separator + 1)
            if (!isIpv4Literal(address)) return null
        }

        val port = portText.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        return Endpoint(address, port)
    }

    private fun queryTxt(resolver: String, host: String): List<String> {
        val url = resolver.toHttpUrl().newBuilder()
            .addQueryParameter("name", host)
            .addQueryParameter("type", "TXT")
            .build()
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/dns-json")
            .get()
            .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("DoH returned HTTP ${response.code}")
            val body = response.body?.string() ?: error("DoH returned an empty body")
            val root = JsonUtil.parseString(body)?.takeIf { it.isJsonObject }?.asJsonObject
                ?: error("DoH returned invalid JSON")
            if (root.get("Status")?.asInt != 0) return emptyList()
            return root.getAsJsonArray("Answer")
                ?.mapNotNull { answer ->
                    answer.takeIf { it.isJsonObject }
                        ?.asJsonObject
                        ?.takeIf { it.get("type")?.asInt == TXT_RECORD_TYPE }
                        ?.get("data")
                        ?.asString
                }
                .orEmpty()
        }
    }

    private fun isIpLiteral(value: String): Boolean = isIpv4Literal(value) || isIpv6Literal(value)

    private fun isIpv4Literal(value: String): Boolean {
        val parts = value.split('.')
        return parts.size == 4 && parts.all { part ->
            if (part.isEmpty() || !part.all(Char::isDigit)) return@all false
            val octet = part.toIntOrNull() ?: return@all false
            octet in 0..255
        }
    }

    private fun isIpv6Literal(value: String): Boolean {
        if (!value.contains(':') || value.any { it != ':' && it !in '0'..'9' && it.lowercaseChar() !in 'a'..'f' }) return false
        return runCatching { InetAddress.getByName(value).hostAddress }.isSuccess
    }
}
