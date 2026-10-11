package com.pawan.routerportscanner

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.widget.*
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val ports = linkedMapOf(
        21 to "FTP", 22 to "SSH", 23 to "Telnet", 53 to "DNS", 80 to "HTTP",
        139 to "NetBIOS", 443 to "HTTPS", 445 to "SMB", 554 to "RTSP",
        3389 to "RDP", 8080 to "HTTP-alt", 8443 to "HTTPS-alt"
    )
    private val executor = Executors.newFixedThreadPool(16)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 48, 36, 36)
        }
        val title = TextView(this).apply { text = "Wi-Fi Security Scanner"; textSize = 26f }
        val note = TextView(this).apply {
            text = "For devices you own or are authorized to test. Discovery and checks stay on your local network."
            textSize = 14f
            setPadding(0, 12, 0, 20)
        }
        val discover = Button(this).apply { text = "Scan Wi-Fi Devices" }
        val devices = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val ip = EditText(this).apply {
            setText(localIpv4()?.let { networkBase(it) + ".1" } ?: "192.168.0.1")
            hint = "Device IP address"
            inputType = InputType.TYPE_CLASS_TEXT
        }
        val scan = Button(this).apply { text = "Security Scan Selected IP" }
        val progress = ProgressBar(this).apply { visibility = ProgressBar.GONE }
        val status = TextView(this).apply { textSize = 16f; setPadding(0, 20, 0, 10) }
        val results = TextView(this).apply { textSize = 16f; setTextIsSelectable(true) }

        root.addView(title); root.addView(note); root.addView(discover); root.addView(devices)
        root.addView(ip); root.addView(scan)
        root.addView(progress, LinearLayout.LayoutParams(-1, 80).apply { gravity = Gravity.CENTER })
        root.addView(status); root.addView(results)
        setContentView(ScrollView(this).apply { addView(root) })

        discover.setOnClickListener {
            val mine = localIpv4()
            if (mine == null) {
                Toast.makeText(this, "Connect to Wi-Fi first", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val base = networkBase(mine)
            discover.isEnabled = false
            scan.isEnabled = false
            progress.visibility = ProgressBar.VISIBLE
            devices.removeAllViews()
            results.text = ""
            status.text = "Discovering devices on $base.0/24…"
            executor.execute {
                val found = discoverHosts(base)
                runOnUiThread {
                    status.text = "Found ${found.size} responding device${if (found.size == 1) "" else "s"}. Tap an IP to select it."
                    found.forEach { host ->
                        devices.addView(Button(this).apply {
                            text = "$host  •  ${identifyDevice(host, mine, base)}"
                            setOnClickListener {
                                ip.setText(host)
                                status.text = "Selected $host. Tap Security Scan Selected IP."
                            }
                        })
                    }
                    if (found.isEmpty()) {
                        results.text = "No devices responded to the safe discovery probes. Some devices ignore these probes even when connected."
                    }
                    progress.visibility = ProgressBar.GONE
                    discover.isEnabled = true
                    scan.isEnabled = true
                }
            }
        }

        scan.setOnClickListener {
            val host = ip.text.toString().trim()
            if (!validIpv4(host) || !isPrivateIpv4(host)) {
                Toast.makeText(this, "Enter a private local IPv4 address", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            scan.isEnabled = false
            discover.isEnabled = false
            progress.visibility = ProgressBar.VISIBLE
            results.text = ""
            status.text = "Checking common services on $host…"
            executor.execute {
                val open = mutableListOf<Pair<Int, String>>()
                ports.forEach { (port, service) ->
                    if (isPortOpen(host, port, 500)) open += port to service
                }
                val assessment = riskAssessment(open)
                runOnUiThread {
                    results.text = buildString {
                        append("IP: $host\n")
                        append("Risk: ${assessment.first}\n\n")
                        if (open.isEmpty()) append("No common TCP services responded.\n")
                        else {
                            append("Open services:\n")
                            open.forEach { (port, service) -> append("• $port — $service\n") }
                        }
                        append("\nWhy: ${assessment.second}\n\n")
                        append("Guidance: ${assessment.third}")
                    }
                    status.text = "Security scan complete"
                    progress.visibility = ProgressBar.GONE
                    scan.isEnabled = true
                    discover.isEnabled = true
                }
            }
        }
    }

    private fun discoverHosts(base: String): List<String> {
        val pool = Executors.newFixedThreadPool(32)
        try {
            val futures = (1..254).map { n ->
                pool.submit<String?> {
                    val host = "$base.$n"
                    val reachable = try {
                        Inet4Address.getByName(host).isReachable(250)
                    } catch (_: Exception) { false }
                    if (reachable || isPortOpen(host, 80, 180) || isPortOpen(host, 443, 180) ||
                        isPortOpen(host, 53, 180) || isPortOpen(host, 445, 180)) host else null
                }
            }
            return futures.mapNotNull { try { it.get() } catch (_: Exception) { null } }
                .distinct().sortedBy { it.substringAfterLast('.').toIntOrNull() ?: 999 }
        } finally {
            pool.shutdownNow()
        }
    }

    private fun identifyDevice(host: String, mine: String, base: String): String {
        if (host == mine) return "This phone"
        if (host == "$base.1") return "Likely router / gateway"

        val hostname = try {
            val resolved = InetAddress.getByName(host).canonicalHostName
            if (resolved != host && !resolved.equals("localhost", true)) resolved else null
        } catch (_: Exception) { null }
        if (!hostname.isNullOrBlank()) return "Hostname: $hostname"

        return when {
            isPortOpen(host, 3389, 220) -> "Likely Windows PC"
            isPortOpen(host, 445, 220) || isPortOpen(host, 139, 220) -> "Likely computer / NAS"
            isPortOpen(host, 554, 220) -> "Likely camera / media device"
            isPortOpen(host, 80, 220) || isPortOpen(host, 443, 220) || isPortOpen(host, 8080, 220) -> "Likely web-managed device"
            else -> "Unknown device"
        }
    }

    private fun isPortOpen(host: String, port: Int, timeout: Int): Boolean =
        try { Socket().use { it.connect(InetSocketAddress(host, port), timeout) }; true }
        catch (_: Exception) { false }

    private fun riskAssessment(open: List<Pair<Int, String>>): Triple<String, String, String> {
        val numbers = open.map { it.first }.toSet()
        val high = numbers.intersect(setOf(21, 23, 139, 445, 3389))
        val medium = numbers.intersect(setOf(22, 80, 554, 8080))
        return when {
            high.isNotEmpty() -> Triple(
                "HIGH",
                "A commonly sensitive or legacy service is reachable: ${high.sorted().joinToString()}. An open port alone does not prove a vulnerability.",
                "If you do not need these services, disable them. Keep the device updated, use strong unique credentials, and disable internet-facing remote access."
            )
            medium.isNotEmpty() -> Triple(
                "MEDIUM",
                "One or more administration, web, or media services are reachable on the LAN. This is not proof the device is vulnerable.",
                "Confirm each service is expected, update the device, use strong unique credentials, and prefer encrypted management such as HTTPS."
            )
            else -> Triple(
                "LOW",
                "No higher-risk common TCP services were found in this limited check.",
                "Keep firmware and apps updated. This scan is not a guarantee that the device has no vulnerabilities."
            )
        }
    }

    private fun localIpv4(): String? {
        return try {
            NetworkInterface.getNetworkInterfaces().toList()
                .flatMap { it.inetAddresses.toList() }
                .filterIsInstance<Inet4Address>()
                .firstOrNull { !it.isLoopbackAddress && it.isSiteLocalAddress }
                ?.hostAddress
        } catch (_: Exception) { null }
    }

    private fun networkBase(ip: String): String = ip.substringBeforeLast('.')

    private fun validIpv4(s: String): Boolean {
        val p = s.split(".")
        return p.size == 4 && p.all { it.toIntOrNull() in 0..255 }
    }

    private fun isPrivateIpv4(s: String): Boolean {
        if (!validIpv4(s)) return false
        val p = s.split(".").map { it.toInt() }
        return p[0] == 10 || (p[0] == 172 && p[1] in 16..31) || (p[0] == 192 && p[1] == 168)
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
