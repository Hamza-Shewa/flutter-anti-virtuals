package dev.shewa.flutter_anti_virtuals

import android.content.Context
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings

/** What matters about one network for VPN and proxy detection. */
internal data class NetworkState(val id: String, val vpn: Boolean, val proxy: String?)

internal object NetworkSignature {
    /** Same string for the same set of networks, whatever order they come in. */
    fun of(networks: List<NetworkState>, defaultProxy: String?): String =
        networks.map { "${it.id}|vpn=${it.vpn}|proxy=${it.proxy.orEmpty()}" }
            .sorted()
            .joinToString(";") + "#" + defaultProxy.orEmpty()
}

/**
 * Calls [onChange] when a network appears, disappears, becomes or stops being a VPN, or
 * changes its proxy. The state that exists when [start] is called is the baseline and does
 * not produce a call, so only real changes reach the guard.
 */
internal class NetworkWatcher(context: Context, private val onChange: () -> Unit) {
    private val resolver = context.contentResolver
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private val main = Handler(Looper.getMainLooper())
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var observer: ContentObserver? = null
    private var last = ""
    private var active = false

    fun start() {
        val manager = cm ?: throw IllegalStateException("ConnectivityManager is not available")
        active = true
        last = signature()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = refresh()
            override fun onLost(network: Network) = refresh()
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = refresh()
            override fun onLinkPropertiesChanged(network: Network, lp: android.net.LinkProperties) = refresh()
        }
        // The default request leaves VPNs out; without removing NOT_VPN a VPN never shows up.
        val request = NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.registerNetworkCallback(request, cb, main)
        } else {
            manager.registerNetworkCallback(request, cb)
        }
        callback = cb
        // A proxy set globally (for example with adb) does not always reach LinkProperties.
        try {
            val obs = object : ContentObserver(main) {
                override fun onChange(selfChange: Boolean) = refresh()
            }
            resolver.registerContentObserver(
                Settings.Global.getUriFor(Settings.Global.HTTP_PROXY), false, obs,
            )
            observer = obs
        } catch (_: Throwable) {
        }
    }

    fun stop() {
        active = false
        try {
            callback?.let { cm?.unregisterNetworkCallback(it) }
        } catch (_: Throwable) {
        }
        callback = null
        observer?.let {
            try {
                resolver.unregisterContentObserver(it)
            } catch (_: Throwable) {
            }
        }
        observer = null
    }

    // Callbacks arrive on binder threads on older Android versions; compare on the main thread.
    private fun refresh() {
        main.post {
            if (!active) return@post
            val now = signature()
            if (now != last) {
                last = now
                onChange()
            }
        }
    }

    private fun signature(): String {
        val manager = cm ?: return ""
        val states = mutableListOf<NetworkState>()
        try {
            @Suppress("DEPRECATION")
            manager.allNetworks.forEach { network ->
                val caps = manager.getNetworkCapabilities(network)
                val proxy = manager.getLinkProperties(network)?.httpProxy
                states += NetworkState(
                    id = network.toString(),
                    vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true ||
                        caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == false,
                    proxy = proxy?.let { "${it.host}:${it.port}${it.pacFileUrl?.toString().orEmpty()}" },
                )
            }
        } catch (_: Throwable) {
        }
        val default = try {
            manager.defaultProxy?.let { "${it.host}:${it.port}${it.pacFileUrl?.toString().orEmpty()}" }
        } catch (_: Throwable) {
            null
        }
        return NetworkSignature.of(states, default)
    }
}
