package dev.shewa.flutter_anti_virtuals

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings

/** The one definition of "this network is a VPN", shared by the scan and the watcher. */
internal fun NetworkCapabilities?.isVpn(): Boolean =
    this?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true ||
        this?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == false

/** Broadcast the system sends after it applied a changed proxy (not exposed in the SDK). */
private const val PROXY_CHANGE_ACTION = "android.intent.action.PROXY_CHANGE"

internal fun ProxyInfo?.describe(): String? =
    this?.let { "${it.host}:${it.port}${it.pacFileUrl?.toString().orEmpty()}" }

/** What matters about one network for VPN and proxy detection. */
internal data class NetworkState(val id: String, val vpn: Boolean, val proxy: String?)

internal object NetworkSignature {
    /** Same string for the same set of networks, whatever order they come in. */
    fun of(networks: Collection<NetworkState>, defaultProxy: String?): String =
        networks.map { "${it.id}|vpn=${it.vpn}|proxy=${it.proxy.orEmpty()}" }
            .sorted()
            .joinToString(";") + "#" + defaultProxy.orEmpty()
}

/**
 * Calls [onChange] when a network appears, disappears, becomes or stops being a VPN, or
 * changes its proxy. The state that exists when [start] is called is the baseline and does
 * not produce a call, so only real changes reach the guard.
 *
 * The baseline is read once with a few binder calls. After that the state is kept up to date
 * from the arguments the callbacks already carry, so the frequent capability updates (signal
 * strength, bandwidth estimates) cost a map update and a string compare on the main thread,
 * not more IPC.
 */
internal class NetworkWatcher(context: Context, private val onChange: () -> Unit) {
    private val appContext = context.applicationContext ?: context
    private val resolver = context.contentResolver
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private val main = Handler(Looper.getMainLooper())
    private val networks = HashMap<Network, NetworkState>()
    private var defaultProxy: String? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var observer: ContentObserver? = null
    private var proxyReceiver: BroadcastReceiver? = null
    private var last = ""
    private var active = false

    fun start() {
        val manager = cm ?: throw IllegalStateException("ConnectivityManager is not available")
        active = true
        seed(manager)
        last = NetworkSignature.of(networks.values, defaultProxy)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = update(network) { it }
            override fun onLost(network: Network) = update(network, remove = true) { it }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val vpn = caps.isVpn()
                update(network) { it.copy(vpn = vpn) }
            }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                val proxy = lp.httpProxy.describe()
                update(network) { it.copy(proxy = proxy) }
            }
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
        // The settings observer is not enough on its own: it does not fire when the value is
        // set (only when it is deleted) on current Android. The system sends PROXY_CHANGE once
        // the connectivity service has applied the new proxy, so `defaultProxy` is current
        // when it arrives.
        try {
            val rec = object : BroadcastReceiver() {
                override fun onReceive(c: Context, intent: Intent) = refreshProxy()
            }
            val filter = IntentFilter(PROXY_CHANGE_ACTION)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                appContext.registerReceiver(rec, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                appContext.registerReceiver(rec, filter)
            }
            proxyReceiver = rec
        } catch (_: Throwable) {
        }
        try {
            val obs = object : ContentObserver(main) {
                override fun onChange(selfChange: Boolean) = refreshProxy()
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
        proxyReceiver?.let {
            try {
                appContext.unregisterReceiver(it)
            } catch (_: Throwable) {
            }
        }
        proxyReceiver = null
        networks.clear()
    }

    private fun seed(manager: ConnectivityManager) {
        try {
            @Suppress("DEPRECATION")
            manager.allNetworks.forEach { network ->
                networks[network] = NetworkState(
                    id = network.toString(),
                    vpn = manager.getNetworkCapabilities(network).isVpn(),
                    proxy = manager.getLinkProperties(network)?.httpProxy.describe(),
                )
            }
        } catch (_: Throwable) {
        }
        defaultProxy = readDefaultProxy()
    }

    private fun refreshProxy() {
        if (!active) return
        defaultProxy = readDefaultProxy()
        publish()
    }

    private fun readDefaultProxy(): String? = try {
        cm?.defaultProxy.describe()
    } catch (_: Throwable) {
        null
    }

    // Callbacks come on the main thread from Android 8 and on a binder thread before; the
    // state is only touched on the main thread.
    private fun update(network: Network, remove: Boolean = false, change: (NetworkState) -> NetworkState) {
        main.post {
            if (!active) return@post
            if (remove) {
                networks.remove(network)
            } else {
                val current = networks[network] ?: NetworkState(network.toString(), vpn = false, proxy = null)
                networks[network] = change(current)
            }
            publish()
        }
    }

    private fun publish() {
        val now = NetworkSignature.of(networks.values, defaultProxy)
        if (now != last) {
            last = now
            onChange()
        }
    }
}
