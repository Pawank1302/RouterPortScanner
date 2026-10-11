package com.pawan.routerportscanner

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.widget.*
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val ports = linkedMapOf(22 to "SSH", 53 to "DNS", 80 to "HTTP", 443 to "HTTPS", 554 to "RTSP", 8080 to "HTTP-alt", 8443 to "HTTPS-alt")
    private val executor = Executors.newFixedThreadPool(4)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(36,48,36,36) }
        val title = TextView(this).apply { text = "Router Port Scanner"; textSize = 26f }
        val note = TextView(this).apply { text = "Scan only devices you own or are authorized to test."; textSize = 14f; setPadding(0,12,0,24) }
        val ip = EditText(this).apply { setText("192.168.0.1"); hint = "IP address"; inputType = InputType.TYPE_CLASS_TEXT }
        val scan = Button(this).apply { text = "Scan Ports" }
        val progress = ProgressBar(this).apply { visibility = ProgressBar.GONE }
        val status = TextView(this).apply { textSize = 16f; setPadding(0,20,0,10) }
        val results = TextView(this).apply { textSize = 17f; setTextIsSelectable(true) }
        root.addView(title); root.addView(note); root.addView(ip); root.addView(scan)
        root.addView(progress, LinearLayout.LayoutParams(-1,80).apply { gravity = Gravity.CENTER })
        root.addView(status); root.addView(results)
        setContentView(root)

        scan.setOnClickListener {
            val host = ip.text.toString().trim()
            if (!validIpv4(host)) { Toast.makeText(this, "Enter a valid IPv4 address", Toast.LENGTH_SHORT).show(); return@setOnClickListener }
            scan.isEnabled = false; progress.visibility = ProgressBar.VISIBLE; results.text = ""; status.text = "Scanning $host…"
            executor.execute {
                val lines = ports.map { (port, service) ->
                    val open = try { Socket().use { s -> s.connect(InetSocketAddress(host, port), 700) }; true } catch (_: Exception) { false }
                    "Port $port  •  $service  •  ${if (open) "OPEN" else "NO RESPONSE"}"
                }
                runOnUiThread { results.text = lines.joinToString("\n\n"); status.text = "Scan complete"; progress.visibility = ProgressBar.GONE; scan.isEnabled = true }
            }
        }
    }

    private fun validIpv4(s: String): Boolean {
        val p = s.split("."); return p.size == 4 && p.all { it.toIntOrNull() in 0..255 }
    }

    override fun onDestroy() { executor.shutdownNow(); super.onDestroy() }
}
