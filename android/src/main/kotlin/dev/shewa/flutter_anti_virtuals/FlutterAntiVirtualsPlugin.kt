package dev.shewa.flutter_anti_virtuals

import android.app.Activity
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
    private var calls: CallWatcher? = null
    private var sink: EventChannel.EventSink? = null
    private lateinit var screenshotChannel: EventChannel
    private val screenshots = ScreenshotWatcher()
    private val protector = ScreenProtector()
    private var activity: Activity? = null
    private lateinit var context: Context
    private lateinit var integrity: PlayIntegrity
    private var worker: ExecutorService? = null
    private val mainHandler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        integrity = PlayIntegrity(context)
        worker = Executors.newSingleThreadExecutor()
        channel = MethodChannel(binding.binaryMessenger, "flutter_anti_virtuals")
        channel.setMethodCallHandler(this)
        changes = EventChannel(binding.binaryMessenger, "flutter_anti_virtuals/changes")
        changes.setStreamHandler(this)
        screenshotChannel = EventChannel(binding.binaryMessenger, "flutter_anti_virtuals/screenshots")
        screenshotChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink) =
                screenshots.listen { events.success("screenshot") }

            override fun onCancel(arguments: Any?) = screenshots.stop()
        })
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
        // So is a call starting: scams run while the victim is on the phone.
        try {
            calls = CallWatcher(context) { events.success("call") }.also { it.start() }
        } catch (_: Throwable) {
        }
    }

    override fun onCancel(arguments: Any?) {
        sink = null
        watcher?.stop()
        watcher = null
        displays?.stop()
        displays = null
        calls?.stop()
        calls = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) = attach(binding.activity)

    override fun onDetachedFromActivityForConfigChanges() = detach()

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = attach(binding.activity)

    override fun onDetachedFromActivity() = detach()

    private fun attach(next: Activity) {
        activity = next
        protector.attach(next) { sink?.success("capture") }
        screenshots.attach(next)
    }

    private fun detach() {
        protector.detach()
        screenshots.detach()
        activity = null
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
            "attest" -> {
                val args = call.arguments as? Map<String, Any?>
                val payload = args?.get("payload") as? String
                if (payload == null) {
                    result.error("bad_arguments", "payload is required", null)
                    return
                }
                val project = (args["cloudProjectNumber"] as? Number)?.toLong()
                // The Play Integrity callbacks arrive on the main thread.
                val reply = { outcome: kotlin.Result<Map<String, Any>> ->
                    outcome.fold(
                        onSuccess = { result.success(it) },
                        onFailure = { result.error("attest_failed", it.message, it.javaClass.simpleName) }
                    )
                }
                if (args["playIntegrity"] != "standard") {
                    integrity.requestClassic(payload, project, reply)
                } else if (project == null) {
                    result.error("bad_arguments", "standard requests need a cloudProjectNumber", null)
                } else {
                    integrity.requestStandard(payload, project, reply)
                }
            }
            "prepareIntegrity" -> {
                val project = ((call.arguments as? Map<String, Any?>)?.get("cloudProjectNumber") as? Number)?.toLong()
                if (project == null) {
                    result.error("bad_arguments", "cloudProjectNumber is required", null)
                    return
                }
                integrity.prepare(project) { outcome ->
                    outcome.fold(
                        onSuccess = { result.success(true) },
                        onFailure = { result.error("prepare_failed", it.message, it.javaClass.simpleName) }
                    )
                }
            }
            "showIntegrityDialog" -> {
                val typeCode = ((call.arguments as? Map<String, Any?>)?.get("typeCode") as? Number)?.toInt()
                if (typeCode == null) {
                    result.error("bad_arguments", "typeCode is required", null)
                    return
                }
                val current = activity ?: return result.success("unavailable")
                integrity.showDialog(current, typeCode) { outcome ->
                    outcome.fold(
                        onSuccess = { result.success(it) },
                        onFailure = { result.error("dialog_failed", it.message, it.javaClass.simpleName) }
                    )
                }
            }
            "rebindDevice" -> {
                val executor = worker
                if (executor == null) {
                    result.error("detached", "Plugin is not attached to an engine", null)
                    return
                }
                // Same thread as the scans, so a rebind never races a binding check.
                executor.execute {
                    try {
                        DeviceBinding(context).rebind()
                        mainHandler.post { result.success(true) }
                    } catch (e: Exception) {
                        mainHandler.post { result.error("rebind_failed", e.message, null) }
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
        screenshotChannel.setStreamHandler(null)
        screenshots.stop()
        calls?.stop()
        calls = null
        watcher?.stop()
        watcher = null
        displays?.stop()
        displays = null
        worker?.shutdown()
        worker = null
    }
}
