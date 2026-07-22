package com.securitydashboard.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.*
import timber.log.Timber
import java.io.BufferedReader
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * NetworkMonitor - Comprehensive Local Network Analysis Module
 *
 * Purpose:
 * - Monitor active TCP/UDP connections on the local device
 * - Track listening ports and services
 * - Analyze network interfaces and configuration
 * - Detect unusual connection patterns for defensive awareness
 * - Provide complete audit trail of network activities
 *
 * IMPORTANT: This tool is designed for:
 * ✓ Personal device monitoring only
 * ✓ Understanding your own device's network behavior
 * ✓ Defensive security learning and awareness
 * ✓ Identifying unexpected outbound connections
 *
 * NOT for:
 * ✗ Scanning networks you don't own
 * ✗ Unauthorized network access
 * ✗ Offensive operations
 *
 * Author: SecurityDashboard Contributors
 * License: MIT
 */
class NetworkMonitor(private val context: Context) {

    // Android system service for connectivity information
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) 
        as ConnectivityManager
    
    // Coroutine scope for background monitoring
    private val scope = CoroutineScope(Dispatchers.IO + Job())
    
    // List of listeners that get notified when network state changes
    private val stateListeners = mutableListOf<(NetworkState) -> Unit>()
    
    // List of listeners for connection events
    private val connectionListeners = mutableListOf<(ConnectionEvent) -> Unit>()
    
    // Track previous connections to detect new/closed connections
    private var previousConnections = setOf<Connection>()
    
    // Configuration for monitoring behavior
    private var monitoringConfig = MonitoringConfig()

    // ==================== DATA CLASSES ====================

    /**
     * Represents the overall state of the device's network
     */
    data class NetworkState(
        // Whether device has active internet connection
        val isConnected: Boolean,
        
        // Type of connection: WiFi, Cellular, Ethernet, etc
        val connectionType: String,
        
        // List of currently active connections
        val activeConnections: List<Connection>,
        
        // List of listening ports (services waiting for connections)
        val listeningPorts: List<ListeningPort>,
        
        // Network interface information
        val networkInterfaces: List<NetworkInterface>,
        
        // Summary statistics
        val statistics: NetworkStatistics,
        
        // Timestamp when this state was captured
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Represents a single network connection
     */
    data class Connection(
        // Protocol: TCP or UDP
        val protocol: String,
        
        // Local IP address
        val localAddress: String,
        
        // Local port number
        val localPort: Int,
        
        // Remote IP address
        val remoteAddress: String,
        
        // Remote port number
        val remotePort: Int,
        
        // Connection state: ESTABLISHED, LISTEN, TIME_WAIT, etc
        val state: String,
        
        // Process name if available (requires root on some devices)
        val process: String? = null,
        
        // Unique identifier for this connection
        val id: String = "$protocol:$localAddress:$localPort:$remoteAddress:$remotePort",
        
        // When this connection was first seen
        val timestamp: Long = System.currentTimeMillis()
    ) {
        /**
         * Check if this is a suspicious connection based on patterns
         */
        fun isSuspicious(): Boolean {
            // Flag connections to private IPs from external sources (potential lateral movement)
            val isPrivateRemote = isPrivateIP(remoteAddress)
            val isPrivateLocal = isPrivateIP(localAddress)
            
            // Suspicious if established connection to unfamiliar port
            val suspiciousPort = remotePort !in listOf(80, 443, 53, 22, 21, 25, 143, 110, 3306, 5432)
            
            return isPrivateRemote && suspiciousPort
        }
        
        /**
         * Check if IP is in private range (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
         */
        private fun isPrivateIP(ip: String): Boolean {
            return ip.startsWith("192.168.") || 
                   ip.startsWith("10.") || 
                   (ip.startsWith("172.") && try {
                       val secondOctet = ip.split(".")[1].toInt()
                       secondOctet in 16..31
                   } catch (e: Exception) { false })
        }
    }

    /**
     * Represents a port that's actively listening (accepting connections)
     */
    data class ListeningPort(
        // Port number
        val port: Int,
        
        // Protocol: TCP or UDP
        val protocol: String,
        
        // Service/process using this port
        val service: String,
        
        // Local address listening on
        val address: String,
        
        // When this port started listening
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Information about a network interface (WiFi, cellular, loopback, etc)
     */
    data class NetworkInterface(
        // Interface name: eth0, wlan0, lo, etc
        val name: String,
        
        // Current IP address
        val ipAddress: String,
        
        // Subnet mask/prefix
        val subnetMask: String,
        
        // MAC address
        val macAddress: String,
        
        // Whether interface is currently active
        val isUp: Boolean,
        
        // Interface type
        val type: String
    )

    /**
     * Network statistics for monitoring overview
     */
    data class NetworkStatistics(
        // Total number of active connections
        val totalConnections: Int,
        
        // Number of established connections
        val establishedConnections: Int,
        
        // Number of listening ports
        val listeningPorts: Int,
        
        // Number of suspicious connections detected
        val suspiciousConnections: Int,
        
        // Number of connections to external IPs
        val externalConnections: Int,
        
        // Number of connections to internal IPs
        val internalConnections: Int
    )

    /**
     * Event triggered when a connection is created or closed
     */
    data class ConnectionEvent(
        // Type of event: NEW, CLOSED, STATE_CHANGED, SUSPICIOUS
        val eventType: String,
        
        // The connection involved
        val connection: Connection,
        
        // Description of what happened
        val description: String,
        
        // Severity level: INFO, WARNING, CRITICAL
        val severity: String = "INFO"
    )

    /**
     * Configuration for monitoring behavior
     */
    data class MonitoringConfig(
        // Update interval in milliseconds
        val updateIntervalMs: Long = 3000,
        
        // Whether to flag suspicious connections
        val detectAnomalies: Boolean = true,
        
        // Whether to log all connections
        val enableLogging: Boolean = true,
        
        // Maximum number of connections to track
        val maxConnectionsTracked: Int = 500
    )

    // ==================== PUBLIC API ====================

    /**
     * Initialize the NetworkMonitor (should be called once)
     */
    fun initialize() {
        Timber.i("NetworkMonitor initialized")
        previousConnections = emptySet()
    }

    /**
     * Start actively monitoring network connections
     * This runs a background coroutine that updates network state periodically
     */
    fun startMonitoring() {
        scope.launch {
            Timber.i("Network monitoring started (update interval: ${monitoringConfig.updateIntervalMs}ms)")
            
            while (isActive) {
                try {
                    // Get current network state
                    val state = getNetworkState()
                    
                    // Notify all state listeners
                    notifyStateListeners(state)
                    
                    // Detect connection changes
                    detectConnectionChanges(state.activeConnections)
                    
                    // Wait before next update
                    delay(monitoringConfig.updateIntervalMs)
                    
                } catch (e: Exception) {
                    Timber.e("Error during network monitoring: ${e.message}")
                }
            }
        }
    }

    /**
     * Stop monitoring network activity
     */
    fun stopMonitoring() {
        scope.cancel()
        Timber.i("Network monitoring stopped")
    }

    /**
     * Add a listener for network state changes
     * Listener will be called whenever network state is updated
     */
    fun addStateListener(listener: (NetworkState) -> Unit) {
        stateListeners.add(listener)
        Timber.d("State listener added (total: ${stateListeners.size})")
    }

    /**
     * Add a listener for connection events
     * Listener will be called when connections open, close, or become suspicious
     */
    fun addConnectionListener(listener: (ConnectionEvent) -> Unit) {
        connectionListeners.add(listener)
        Timber.d("Connection listener added (total: ${connectionListeners.size})")
    }

    /**
     * Get the current network state immediately (non-blocking)
     */
    suspend fun getNetworkState(): NetworkState = withContext(Dispatchers.IO) {
        val isConnected = isDeviceConnected()
        val connectionType = getConnectionType()
        val activeConnections = getActiveConnections()
        val listeningPorts = getListeningPorts()
        val networkInterfaces = getNetworkInterfaces()
        val statistics = calculateStatistics(activeConnections, listeningPorts)
        
        return@withContext NetworkState(
            isConnected = isConnected,
            connectionType = connectionType,
            activeConnections = activeConnections,
            listeningPorts = listeningPorts,
            networkInterfaces = networkInterfaces,
            statistics = statistics
        )
    }

    /**
     * Get a detailed report of network activity (formatted for display)
     */
    suspend fun getNetworkReport(): String = withContext(Dispatchers.IO) {
        val state = getNetworkState()
        val report = StringBuilder()
        
        report.append("╔════════════════════════════════════════════════╗\n")
        report.append("║   NETWORK MONITOR - SECURITY ANALYSIS REPORT   ║\n")
        report.append("╚════════════════════════════════════════════════╝\n\n")
        
        // Connection status
        report.append("🌐 CONNECTION STATUS\n")
        report.append("├─ Connected: ${if (state.isConnected) "YES" else "NO"}\n")
        report.append("├─ Type: ${state.connectionType}\n")
        report.append("└─ Time: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(state.timestamp))}\n\n")
        
        // Statistics
        report.append("📊 STATISTICS\n")
        report.append("├─ Active Connections: ${state.statistics.establishedConnections}\n")
        report.append("├─ Listening Ports: ${state.statistics.listeningPorts}\n")
        report.append("├─ External Connections: ${state.statistics.externalConnections}\n")
        report.append("├─ Internal Connections: ${state.statistics.internalConnections}\n")
        report.append("└─ Suspicious Connections: ${state.statistics.suspiciousConnections}\n\n")
        
        // Top listening ports
        if (state.listeningPorts.isNotEmpty()) {
            report.append("🔊 LISTENING PORTS (Top 10)\n")
            state.listeningPorts.take(10).forEach { port ->
                report.append("├─ ${port.address}:${port.port} (${port.protocol}) - ${port.service}\n")
            }
            report.append("\n")
        }
        
        // Active connections
        if (state.activeConnections.isNotEmpty()) {
            report.append("🔗 ACTIVE CONNECTIONS (Top 10)\n")
            state.activeConnections.take(10).forEach { conn ->
                val suspicious = if (conn.isSuspicious()) "⚠️  SUSPICIOUS" else ""
                report.append("├─ ${conn.localAddress}:${conn.localPort} → ${conn.remoteAddress}:${conn.remotePort} [${conn.state}] $suspicious\n")
            }
            if (state.activeConnections.size > 10) {
                report.append("└─ ... and ${state.activeConnections.size - 10} more\n")
            }
            report.append("\n")
        }
        
        // Network interfaces
        if (state.networkInterfaces.isNotEmpty()) {
            report.append("🖧 NETWORK INTERFACES\n")
            state.networkInterfaces.forEach { iface ->
                report.append("├─ ${iface.name}: ${iface.ipAddress} (${if (iface.isUp) "UP" else "DOWN"})\n")
            }
            report.append("\n")
        }
        
        // Warnings
        if (state.statistics.suspiciousConnections > 0) {
            report.append("⚠️  SECURITY WARNINGS\n")
            report.append("└─ ${ state.statistics.suspiciousConnections} suspicious connection(s) detected\n")
            report.append("   Review the connection details above.\n\n")
        }
        
        return@withContext report.toString()
    }

    /**
     * Configure monitoring behavior
     */
    fun setMonitoringConfig(config: MonitoringConfig) {
        monitoringConfig = config
        Timber.i("Monitoring configuration updated: $config")
    }

    // ==================== PRIVATE IMPLEMENTATION ====================

    /**
     * Check if device has active internet connection
     */
    private fun isDeviceConnected(): Boolean {
        val network = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false
        
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    /**
     * Determine the type of network connection
     */
    private fun getConnectionType(): String {
        val network = connectivityManager.activeNetwork ?: return "None"
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return "Unknown"
        
        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Unknown"
        }
    }

    /**
     * Read active TCP connections from /proc/net/tcp
     * This is local analysis only - no network scanning
     */
    private suspend fun getActiveConnections(): List<Connection> = withContext(Dispatchers.IO) {
        val connections = mutableListOf<Connection>()
        
        try {
            // Read TCP connections
            val tcpFile = File("/proc/net/tcp")
            if (tcpFile.exists()) {
                connections.addAll(parseConnectionFile(tcpFile, "TCP"))
            }
            
            // Read UDP connections
            val udpFile = File("/proc/net/udp")
            if (udpFile.exists()) {
                connections.addAll(parseConnectionFile(udpFile, "UDP"))
            }
            
            // Sort by state (established first) then by timestamp
            connections.sortWith(compareBy({ it.state != "ESTABLISHED" }, { it.timestamp }))
            
            // Limit to configured maximum
            return@withContext connections.take(monitoringConfig.maxConnectionsTracked)
            
        } catch (e: Exception) {
            Timber.e("Error reading connections: ${e.message}")
            return@withContext emptyList()
        }
    }

    /**
     * Parse /proc/net/tcp or /proc/net/udp file format
     * Format: local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
     */
    private fun parseConnectionFile(file: File, protocol: String): List<Connection> {
        val connections = mutableListOf<Connection>()
        
        try {
            file.bufferedReader().use { reader ->
                // Skip header line
                reader.readLine()
                
                reader.forEachLine { line ->
                    try {
                        val parts = line.trim().split("\\s+".toRegex())
                        
                        // Need at least 6 fields
                        if (parts.size < 6) return@forEachLine
                        
                        // Parse local address and port
                        val localParts = parts[1].split(":")
                        if (localParts.size != 2) return@forEachLine
                        
                        val localAddress = formatIPAddress(localParts[0])
                        val localPort = localParts[1].toInt(16)
                        
                        // Parse remote address and port
                        val remoteParts = parts[2].split(":")
                        if (remoteParts.size != 2) return@forEachLine
                        
                        val remoteAddress = formatIPAddress(remoteParts[0])
                        val remotePort = remoteParts[1].toInt(16)
                        
                        // Parse state
                        val stateHex = parts[3]
                        val state = parseConnectionState(stateHex)
                        
                        // Create connection object
                        val connection = Connection(
                            protocol = protocol,
                            localAddress = localAddress,
                            localPort = localPort,
                            remoteAddress = remoteAddress,
                            remotePort = remotePort,
                            state = state
                        )
                        
                        connections.add(connection)
                        
                    } catch (e: Exception) {
                        Timber.v("Could not parse connection line: $line")
                    }
                }
            }
        } catch (e: Exception) {
            Timber.e("Error parsing connection file: ${e.message}")
        }
        
        return connections
    }

    /**
     * Get listening ports from /proc/net/tcp
     * Listening state means the port is waiting for incoming connections
     */
    private suspend fun getListeningPorts(): List<ListeningPort> = withContext(Dispatchers.IO) {
        val listeningPorts = mutableListOf<ListeningPort>()
        
        try {
            val tcpFile = File("/proc/net/tcp")
            if (!tcpFile.exists()) return@withContext emptyList()
            
            tcpFile.bufferedReader().use { reader ->
                reader.readLine() // Skip header
                
                reader.forEachLine { line ->
                    try {
                        val parts = line.trim().split("\\s+".toRegex())
                        if (parts.size < 4) return@forEachLine
                        
                        // Check if LISTEN state
                        if (parts[3] != "0A") return@forEachLine // 0A = LISTEN
                        
                        val addressParts = parts[1].split(":")
                        if (addressParts.size != 2) return@forEachLine
                        
                        val address = formatIPAddress(addressParts[0])
                        val port = addressParts[1].toInt(16)
                        
                        listeningPorts.add(
                            ListeningPort(
                                port = port,
                                protocol = "TCP",
                                service = getServiceName(port),
                                address = address
                            )
                        )
                    } catch (e: Exception) {
                        Timber.v("Could not parse listening port: $line")
                    }
                }
            }
        } catch (e: Exception) {
            Timber.e("Error reading listening ports: ${e.message}")
        }
        
        return@withContext listeningPorts.sortedBy { it.port }
    }

    /**
     * Get information about network interfaces
     */
    private suspend fun getNetworkInterfaces(): List<NetworkInterface> = withContext(Dispatchers.IO) {
        val interfaces = mutableListOf<NetworkInterface>()
        
        try {
            java.net.NetworkInterface.getNetworkInterfaces().asSequence().forEach { iface ->
                try {
                    val name = iface.name
                    val isUp = iface.isUp
                    
                    val ipAddress = iface.inetAddresses.asSequence()
                        .filter { !it.isLoopbackAddress }
                        .firstOrNull()
                        ?.hostAddress ?: "N/A"
                    
                    val macAddress = iface.hardwareAddress?.joinToString(":") { "%02x".format(it) } ?: "N/A"
                    
                    interfaces.add(
                        NetworkInterface(
                            name = name,
                            ipAddress = ipAddress,
                            subnetMask = "N/A", // Would need additional parsing
                            macAddress = macAddress,
                            isUp = isUp,
                            type = determineInterfaceType(name)
                        )
                    )
                } catch (e: Exception) {
                    Timber.v("Could not parse interface: ${e.message}")
                }
            }
        } catch (e: Exception) {
            Timber.e("Error reading network interfaces: ${e.message}")
        }
        
        return@withContext interfaces
    }

    /**
     * Calculate network statistics from current connections
     */
    private fun calculateStatistics(
        connections: List<Connection>,
        listeningPorts: List<ListeningPort>
    ): NetworkStatistics {
        val totalConnections = connections.size
        val establishedConnections = connections.count { it.state == "ESTABLISHED" }
        val suspiciousConnections = connections.count { it.isSuspicious() }
        val externalConnections = connections.count { !isPrivateIP(it.remoteAddress) }
        val internalConnections = connections.count { isPrivateIP(it.remoteAddress) }
        
        return NetworkStatistics(
            totalConnections = totalConnections,
            establishedConnections = establishedConnections,
            listeningPorts = listeningPorts.size,
            suspiciousConnections = suspiciousConnections,
            externalConnections = externalConnections,
            internalConnections = internalConnections
        )
    }

    /**
     * Detect new connections, closed connections, and changed states
     */
    private fun detectConnectionChanges(currentConnections: List<Connection>) {
        val currentIds = currentConnections.map { it.id }.toSet()
        val previousIds = previousConnections.map { it.id }.toSet()
        
        // New connections
        val newIds = currentIds - previousIds
        newIds.forEach { id ->
            val connection = currentConnections.find { it.id == id } ?: return@forEach
            notifyConnectionListeners(
                ConnectionEvent(
                    eventType = "NEW",
                    connection = connection,
                    description = "New connection established: ${connection.localAddress}:${connection.localPort} → ${connection.remoteAddress}:${connection.remotePort}",
                    severity = if (connection.isSuspicious()) "WARNING" else "INFO"
                )
            )
        }
        
        // Closed connections
        val closedIds = previousIds - currentIds
        closedIds.forEach { id ->
            val connection = previousConnections.find { it.id == id } ?: return@forEach
            notifyConnectionListeners(
                ConnectionEvent(
                    eventType = "CLOSED",
                    connection = connection,
                    description = "Connection closed: ${connection.localAddress}:${connection.localPort} → ${connection.remoteAddress}:${connection.remotePort}"
                )
            )
        }
        
        previousConnections = currentConnections.toSet()
    }

    /**
     * Notify all state listeners
     */
    private fun notifyStateListeners(state: NetworkState) {
        stateListeners.forEach { listener ->
            try {
                listener(state)
            } catch (e: Exception) {
                Timber.e("Error notifying state listener: ${e.message}")
            }
        }
    }

    /**
     * Notify all connection listeners
     */
    private fun notifyConnectionListeners(event: ConnectionEvent) {
        connectionListeners.forEach { listener ->
            try {
                listener(event)
            } catch (e: Exception) {
                Timber.e("Error notifying connection listener: ${e.message}")
            }
        }
        
        if (monitoringConfig.enableLogging) {
            Timber.i("Connection Event: ${event.eventType} - ${event.description}")
        }
    }

    /**
     * Convert hex IP address to dotted decimal notation
     * Example: 0100007F (loopback) → 127.0.0.1
     */
    private fun formatIPAddress(hex: String): String {
        return try {
            if (hex == "00000000") return "0.0.0.0"
            if (hex.length < 8) return hex
            
            // Convert pairs of hex digits to decimal, then reverse (little-endian)
            val bytes = hex.chunked(2)
                .map { it.toInt(16) }
                .reversed()
            
            bytes.joinToString(".")
        } catch (e: Exception) {
            Timber.w("Could not format IP address: $hex")
            hex
        }
    }

    /**
     * Convert hex connection state to human-readable format
     * Linux kernel TCP states
     */
    private fun parseConnectionState(stateHex: String): String {
        return when (stateHex) {
            "01" -> "ESTABLISHED"
            "02" -> "SYN_SENT"
            "03" -> "SYN_RECV"
            "04" -> "FIN_WAIT1"
            "05" -> "FIN_WAIT2"
            "06" -> "TIME_WAIT"
            "07" -> "CLOSE"
            "08" -> "CLOSE_WAIT"
            "09" -> "LAST_ACK"
            "0A" -> "LISTEN"
            "0B" -> "CLOSING"
            else -> "UNKNOWN($stateHex)"
        }
    }

    /**
     * Get common service name for a port
     */
    private fun getServiceName(port: Int): String {
        return when (port) {
            21 -> "FTP"
            22 -> "SSH"
            23 -> "Telnet"
            25 -> "SMTP"
            53 -> "DNS"
            80 -> "HTTP"
            110 -> "POP3"
            143 -> "IMAP"
            443 -> "HTTPS"
            445 -> "SMB"
            3306 -> "MySQL"
            5432 -> "PostgreSQL"
            5900 -> "VNC"
            3389 -> "RDP"
            8080 -> "HTTP-Alt"
            8443 -> "HTTPS-Alt"
            else -> "Unknown"
        }
    }

    /**
     * Determine interface type from name
     */
    private fun determineInterfaceType(name: String): String {
        return when {
            name.startsWith("wlan") -> "WiFi"
            name.startsWith("eth") -> "Ethernet"
            name.startsWith("tun") || name.startsWith("tap") -> "VPN/Tunnel"
            name == "lo" -> "Loopback"
            name.startsWith("ppp") -> "PPP"
            else -> "Other"
        }
    }

    /**
     * Check if IP is in private range
     */
    private fun isPrivateIP(ip: String): Boolean {
        return ip.startsWith("192.168.") || 
               ip.startsWith("10.") || 
               ip.startsWith("127.") ||
               (ip.startsWith("172.") && try {
                   val secondOctet = ip.split(".")[1].toInt()
                   secondOctet in 16..31
               } catch (e: Exception) { false })
    }
}
