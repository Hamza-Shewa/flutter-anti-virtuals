package dev.shewa.flutter_anti_virtuals

import android.content.Context
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class FlutterAntiVirtualsPlugin : FlutterPlugin, ActivityAware, MethodCallHandler, EventChannel.StreamHandler {
    private lateinit var channel: MethodChannel
    private lateinit var changes: EventChannel
    private var watcher: NetworkWatcher? = null
    private var displays: DisplayWatcher? = null
    private var sink: EventChannel.EventSink? = null
    private val protector = ScreenProtector()
    private lateinit var context: Context
    private var worker: ExecutorService? = null
    private val mainHandler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        worker = Executors.newSingleThreadExecutor()
        channel = MethodChannel(binding.binaryMessenger, "flutter_anti_virtuals")
        channel.setMethodCallHandler(this)
        changes = EventChannel(binding.binaryMessenger, "flutter_anti_virtuals/changes")
        changes.setStreamHandler(this)
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        sink = events
        watcher?.stop()
        displays?.stop()
        val next = NetworkWatcher(context) { events.success("network") }
        try {
            next.start()
            watcher = next
        } catch (e: Throwable) {
            next.stop()
            events.error("watch_failed", e.message, null)
        }
        // Casting or a cable display starting is as relevant as a VPN starting.
        try {
            displays = DisplayWatcher(context, mainHandler) { events.success("capture") }.also { it.start() }
        } catch (_: Throwable) {
        }
    }

    override fun onCancel(arguments: Any?) {
        sink = null
        watcher?.stop()
        watcher = null
        displays?.stop()
        displays = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        protector.attach(binding.activity) { sink?.success("capture") }
    }

    override fun onDetachedFromActivityForConfigChanges() = protector.detach()

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        protector.attach(binding.activity) { sink?.success("capture") }
    }

    override fun onDetachedFromActivity() = protector.detach()

    @Suppress("UNCHECKED_CAST")
    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "scan" -> {
                val config = ScanConfig.from(call.arguments as? Map<String, Any?>)
                // Package, KeyStore and /proc reads are blocking; keep them off the UI thread.
                val executor = worker
                if (executor == null) {
                    result.error("detached", "Plugin is not attached to an engine", null)
                    return
                }
                executor.execute {
                    val report = AntiVirtualScanner(context).scan(config)
                    mainHandler.post { result.success(report) }
                }
            }
            "signPayload" -> {
                val args = call.arguments as? Map<String, Any?>
                val nonce = args?.get("nonce") as? String
                val payload = args?.get("payload") as? String
                val executor = worker
                if (nonce == null || payload == null) {
                    result.error("bad_arguments", "nonce and payload are required", null)
                    return
                }
                if (executor == null) {
                    result.error("detached", "Plugin is not attached to an engine", null)
                    return
                }
                // Key generation can take a while on secure hardware.
                executor.execute {
                    try {
                        val signed = DeviceKey.sign(nonce, payload.toByteArray(Charsets.UTF_8))
                        mainHandler.post { result.success(signed) }
                    } catch (e: Exception) {
                        mainHandler.post { result.error("sign_failed", e.message, null) }
                    }
                }
            }
            "setScreenProtection" -> {
                val config = ScreenProtectionConfig.from(call.arguments as? Map<String, Any?>)
                result.success(protector.apply(config))
            }
            else -> result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        changes.setStreamHandler(null)
        watcher?.stop()
        watcher = null
        displays?.stop()
        displays = null
        worker?.shutdown()
        worker = null
    }
}
