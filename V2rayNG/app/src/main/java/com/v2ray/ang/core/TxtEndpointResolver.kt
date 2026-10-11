package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

/**
 * Discovers runtime dial endpoints from DNS TXT records such as `ip:port`.
 *
 * Ordinary A/AAAA success must not skip TXT: entry domains may be poisoned or
 * may publish both record types. Only a parseable literal `IP:port` TXT record
 * replaces the outbound address and port.
 */
object TxtEndpointResolver {
    data class Endpoint(val address: String, val port: Int)

    fun interface FileDescriptorProtector {
        fun protect(fileDescriptor: Int): Boolean
    }

    private const val QUERY_TIMEOUT_SECONDS = 3L
    private const val TXT_RECORD_TYPE = 16
    private const val DNS_CLASS_IN = 1
    private const val CACHE_KEY_PREFIX = "txt_endpoint_cache_"
    private val random = SecureRandom()

    @Volatile
    var fileDescriptorProtector: FileDescriptorProtector? = null

    private data class CachedEntry(val endpoint: Endpoint, val expiresAtMs: Long)

    private val cache = ConcurrentHashMap<String, CachedEntry>()
    private val udpResolvers = listOf("223.5.5.5", "119.29.29.29")
    private val dohResolvers = listOf(
        "https://dns.alidns.com/resolve",
        "https://doh.pub/dns-query",
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
    )
    private val dohPinnedAddresses = mapOf(
        "dns.alidns.com" to byteArrayOf(223.toByte(), 5, 5, 5),
        "doh.pub" to byteArrayOf(1, 12, 12, 12),
        "dns.google" to byteArrayOf(8, 8, 8, 8),
        "cloudflare-dns.com" to byteArrayOf(1, 1, 1, 1),
    )

    fun prefetch(host: String) {
        val normalizedHost = host.trim().removeSuffix(".")
        if (normalizedHost.isEmpty() || isIpLiteral(normalizedHost)) return
        if (cached(normalizedHost) != null) return
        resolve(normalizedHost)
    }

    fun resolve(host: String): Endpoint? {
        val normalizedHost = host.trim().removeSuffix(".")
        if (normalizedHost.isEmpty() || isIpLiteral(normalizedHost)) return null
        cached(normalizedHost)?.let { return it }

        val (queried, ttlSeconds) = queryAll(normalizedHost)
        if (queried.isEmpty()) return null
        val endpoint = queried[random.nextInt(queried.size)]
        persist(normalizedHost, endpoint, ttlSeconds)
        LogUtil.i(AppConfig.TAG, "TXT endpoint: resolved ${endpoint.address}:${endpoint.port} ttl=${ttlSeconds}s")
        return endpoint
    }

    /**
     * TXT `IP:port` wins when present. Literal IPs and domains without a parseable
     * TXT endpoint keep the profile address and port.
     */
    internal fun prefersTxt(host: String?): Boolean {
        val value = host?.trim()?.removeSuffix(".")?.removeSurrounding("[", "]").orEmpty()
        return value.isNotEmpty() && !isIpLiteral(value)
    }

    fun resolvedDial(host: String?, port: String?): Pair<String, Int>? {
        val profilePort = port?.toIntOrNull() ?: return null
        val server = host?.trim().orEmpty()
        if (server.isEmpty()) return null
        val endpoint = if (prefersTxt(server)) resolve(server) else null
        return pickDial(server, profilePort, endpoint)
    }

    internal fun pickDial(
        host: String,
        profilePort: Int,
        endpoint: Endpoint?,
    ): Pair<String, Int> =
        if (endpoint != null) endpoint.address to endpoint.port else host to profilePort

    internal fun formatEndpoint(endpoint: Endpoint): String =
        if (endpoint.address.contains(':')) "[${endpoint.address}]:${endpoint.port}"
        else "${endpoint.address}:${endpoint.port}"

    internal fun parseEndpoints(records: List<String>): List<Endpoint> =
        records.mapNotNull(::parseEndpoint).distinct()

    internal fun parseEndpoint(record: String): Endpoint? {
        val value = unwrapTxtPayload(record)
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

    internal fun unwrapTxtPayload(record: String): String {
        var value = record.trim()
        while (value.length >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length - 1).trim()
        }
        return value
    }

    internal fun parseDnsTxtResponse(packet: ByteArray): Pair<List<String>, Int> {
        if (packet.size < 12) return emptyList<String>() to 0
        val answerCount = ((packet[6].toInt() and 0xff) shl 8) or (packet[7].toInt() and 0xff)
        var offset = 12
        val questionCount = ((packet[4].toInt() and 0xff) shl 8) or (packet[5].toInt() and 0xff)
        repeat(questionCount) {
            offset = skipName(packet, offset)
            offset += 4
        }
        val records = mutableListOf<String>()
        var minTtl = Int.MAX_VALUE
        repeat(answerCount) {
            if (offset + 10 > packet.size) return records to minTtl.coerceAtLeast(0)
            offset = skipName(packet, offset)
            val type = readU16(packet, offset)
            val ttl = readU32(packet, offset + 4)
            val rdLength = readU16(packet, offset + 8)
            offset += 10
            val recordEnd = offset + rdLength
            if (recordEnd > packet.size) return records to minTtl.coerceAtLeast(0)
            if (ttl in 1 until minTtl) minTtl = ttl
            if (type == TXT_RECORD_TYPE) {
                records.addAll(parseTxtRdata(packet.copyOfRange(offset, recordEnd)))
            }
            offset = recordEnd
        }
        return records to if (minTtl == Int.MAX_VALUE) 60 else minTtl
    }

    internal fun cacheTtlMs(ttlSeconds: Int): Long = ttlSeconds.coerceAtLeast(0) * 1000L

    internal fun formatCachedRecord(endpoint: Endpoint, expiresAtMs: Long): String =
        "${formatEndpoint(endpoint)}|$expiresAtMs"

    internal fun parseCachedRecord(value: String, nowMs: Long): Endpoint? {
        val separator = value.lastIndexOf('|')
        if (separator <= 0 || separator == value.lastIndex) return null
        val expiresAtMs = value.substring(separator + 1).toLongOrNull() ?: return null
        if (expiresAtMs <= nowMs) return null
        return parseEndpoint(value.substring(0, separator))
    }

    private fun cached(host: String): Endpoint? {
        val now = System.currentTimeMillis()
        cache[host]?.let { entry ->
            if (entry.expiresAtMs > now) return entry.endpoint
            cache.remove(host)
        }
        val persisted = runCatching {
            MmkvManager.decodeSettingsString(CACHE_KEY_PREFIX + host)
        }.getOrNull() ?: return null
        val endpoint = parseCachedRecord(persisted, now)
        if (endpoint == null) {
            runCatching { MmkvManager.encodeSettings(CACHE_KEY_PREFIX + host, null as String?) }
            return null
        }
        val expiresAtMs = persisted.substringAfterLast('|').toLongOrNull() ?: return endpoint
        cache[host] = CachedEntry(endpoint, expiresAtMs)
        return endpoint
    }

    private fun persist(host: String, endpoint: Endpoint, ttlSeconds: Int) {
        val ttlMs = cacheTtlMs(ttlSeconds)
        if (ttlMs <= 0L) {
            cache.remove(host)
            runCatching { MmkvManager.encodeSettings(CACHE_KEY_PREFIX + host, null as String?) }
            return
        }
        val entry = CachedEntry(endpoint, System.currentTimeMillis() + ttlMs)
        cache[host] = entry
        runCatching {
            MmkvManager.encodeSettings(CACHE_KEY_PREFIX + host, formatCachedRecord(endpoint, entry.expiresAtMs))
        }
    }

    private fun queryAll(host: String): Pair<List<Endpoint>, Int> {
        for (server in udpResolvers) {
            try {
                val (records, ttl) = queryUdpTxt(server, host)
                val endpoints = parseEndpoints(records)
                if (endpoints.isNotEmpty()) return endpoints to ttl
                // A completed lookup with no parseable IP:port TXT is a negative
                // answer: fall back to the profile address/port instead of waiting
                // on every remaining resolver.
                return emptyList<Endpoint>() to 0
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "TXT endpoint: UDP resolver failed", e)
            }
        }
        for (resolver in dohResolvers) {
            try {
                val (records, ttl) = queryDohTxt(resolver, host)
                val endpoints = parseEndpoints(records)
                if (endpoints.isNotEmpty()) return endpoints to ttl
                return emptyList<Endpoint>() to 0
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "TXT endpoint: DoH resolver failed", e)
            }
        }
        return emptyList<Endpoint>() to 0
    }

    private fun queryUdpTxt(server: String, host: String): Pair<List<String>, Int> {
        val id = random.nextInt(0x10000)
        val query = buildDnsQuery(id, host)
        DatagramSocket().use { socket ->
            protectDatagram(socket)
            socket.soTimeout = (QUERY_TIMEOUT_SECONDS * 1000L).toInt()
            socket.send(DatagramPacket(query, query.size, InetAddress.getByName(server), 53))
            val buffer = ByteArray(2048)
            val incoming = DatagramPacket(buffer, buffer.size)
            socket.receive(incoming)
            val packet = incoming.data.copyOf(incoming.length)
            if (packet.size < 12 || readU16(packet, 0) != id) error("DNS response id mismatch")
            return parseDnsTxtResponse(packet)
        }
    }

    private fun queryDohTxt(resolver: String, host: String): Pair<List<String>, Int> {
        val url = resolver.toHttpUrl().newBuilder()
            .addQueryParameter("name", host)
            .addQueryParameter("type", "TXT")
            .build()
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/dns-json")
            .get()
            .build()
        httpClient().newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("DoH returned HTTP ${response.code}")
            val body = response.body?.string() ?: error("DoH returned an empty body")
            val root = JsonUtil.parseString(body)?.takeIf { it.isJsonObject }?.asJsonObject
                ?: error("DoH returned invalid JSON")
            val status = root.get("Status")?.takeIf { it.isJsonPrimitive }?.asInt
            if (status != null && status != 0) return emptyList<String>() to 0
            var minTtl = 60
            val records = root.get("Answer")
                ?.takeIf { it.isJsonArray }
                ?.asJsonArray
                ?.mapNotNull { answer ->
                    val obj = answer.takeIf { it.isJsonObject }?.asJsonObject ?: return@mapNotNull null
                    val type = jsonNumber(obj, "type") ?: return@mapNotNull null
                    jsonNumber(obj, "TTL")?.takeIf { it in 1 until minTtl }?.let { minTtl = it }
                    obj.takeIf { type == TXT_RECORD_TYPE }?.get("data")?.asString
                }
                .orEmpty()
            return records to minTtl
        }
    }

    internal fun buildDnsQuery(id: Int, host: String): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, id)
        writeU16(out, 0x0100)
        writeU16(out, 1)
        writeU16(out, 0)
        writeU16(out, 0)
        writeU16(out, 0)
        host.trim('.').split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        writeU16(out, TXT_RECORD_TYPE)
        writeU16(out, DNS_CLASS_IN)
        return out.toByteArray()
    }

    private fun parseTxtRdata(rdata: ByteArray): List<String> {
        val records = mutableListOf<String>()
        var offset = 0
        while (offset < rdata.size) {
            val length = rdata[offset].toInt() and 0xff
            offset += 1
            val end = offset + length
            if (end > rdata.size) break
            records += String(rdata, offset, length, Charsets.UTF_8)
            offset = end
        }
        return records
    }

    private fun skipName(packet: ByteArray, start: Int): Int {
        var offset = start
        var jumped = false
        var safety = 0
        while (safety++ < 128) {
            if (offset >= packet.size) return packet.size
            val label = packet[offset].toInt() and 0xff
            if (label == 0) return if (jumped) start else offset + 1
            if (label and 0xc0 == 0xc0) {
                if (!jumped) return offset + 2
                offset = ((label and 0x3f) shl 8) or (packet[offset + 1].toInt() and 0xff)
                continue
            }
            offset += label + 1
        }
        return packet.size
    }

    private fun httpClient(): OkHttpClient =
        OkHttpClient.Builder()
            .connectTimeout(QUERY_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(QUERY_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .dns(PinnedDohDns())
            .socketFactory(GuardedSocketFactory())
            .build()

    private fun protectDatagram(socket: DatagramSocket) {
        val protector = fileDescriptorProtector ?: return
        runCatching {
            val pfdClass = Class.forName("android.os.ParcelFileDescriptor")
            val pfd = pfdClass.getMethod("fromDatagramSocket", DatagramSocket::class.java).invoke(null, socket)
            val fd = pfdClass.getMethod("getFd").invoke(pfd) as Int
            protector.protect(fd)
        }
    }

    private fun protectStream(socket: Socket) {
        val protector = fileDescriptorProtector ?: return
        runCatching {
            val pfdClass = Class.forName("android.os.ParcelFileDescriptor")
            val pfd = pfdClass.getMethod("fromSocket", Socket::class.java).invoke(null, socket)
            val fd = pfdClass.getMethod("getFd").invoke(pfd) as Int
            protector.protect(fd)
        }
    }

    private fun jsonNumber(obj: com.google.gson.JsonObject, name: String): Int? {
        val value = obj.get(name)?.takeIf { it.isJsonPrimitive } ?: return null
        return runCatching { value.asInt }.getOrNull()
            ?: value.asString.toIntOrNull()
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xff)
        out.write(value and 0xff)
    }

    private fun readU16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

    private fun readU32(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)

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

    private class PinnedDohDns : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val pinned = dohPinnedAddresses[hostname] ?: return Dns.SYSTEM.lookup(hostname)
            return listOf(InetAddress.getByAddress(hostname, pinned))
        }
    }

    private class GuardedSocketFactory : SocketFactory() {
        override fun createSocket(): Socket = guarded(Socket())

        override fun createSocket(host: String, port: Int): Socket {
            val socket = guarded(Socket())
            socket.connect(InetSocketAddress(host, port), (QUERY_TIMEOUT_SECONDS * 1000L).toInt())
            return socket
        }

        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
            val socket = guarded(Socket())
            socket.bind(InetSocketAddress(localHost, localPort))
            socket.connect(InetSocketAddress(host, port), (QUERY_TIMEOUT_SECONDS * 1000L).toInt())
            return socket
        }

        override fun createSocket(host: InetAddress, port: Int): Socket {
            val socket = guarded(Socket())
            socket.connect(InetSocketAddress(host, port), (QUERY_TIMEOUT_SECONDS * 1000L).toInt())
            return socket
        }

        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
            val socket = guarded(Socket())
            socket.bind(InetSocketAddress(localAddress, localPort))
            socket.connect(InetSocketAddress(address, port), (QUERY_TIMEOUT_SECONDS * 1000L).toInt())
            return socket
        }

        private fun guarded(socket: Socket): Socket {
            protectStream(socket)
            return socket
        }
    }
}
