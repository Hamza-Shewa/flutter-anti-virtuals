package dev.shewa.flutter_anti_virtuals

import android.content.Context
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class FlutterAntiVirtualsPlugin : FlutterPlugin, MethodCallHandler, EventChannel.StreamHandler {
    private lateinit var channel: MethodChannel
    private lateinit var changes: EventChannel
    private var watcher: NetworkWatcher? = null
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
        watcher?.stop()
        val next = NetworkWatcher(context) { events.success("network") }
        try {
            next.start()
            watcher = next
        } catch (e: Throwable) {
            next.stop()
            events.error("watch_failed", e.message, null)
        }
    }

    override fun onCancel(arguments: Any?) {
        watcher?.stop()
        watcher = null
    }

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
            else -> result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        changes.setStreamHandler(null)
        watcher?.stop()
        watcher = null
        worker?.shutdown()
        worker = null
    }
}
