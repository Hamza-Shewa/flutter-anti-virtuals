package dev.shewa.flutter_anti_virtuals

/** Package names the scanner recognises. Extend as new tools appear. */
internal object KnownPackages {
    val mockLocation = setOf(
        "com.lexa.fakegps",
        "com.incorporateapps.fakegps.fre",
        "com.blogspot.newapphorizons.fakegps",
        "com.fakegps.mock",
        "com.theappninjas.fakegpsjoystick",
        "ru.gavrikov.mocklocations",
        "com.rosteam.gpsemulator",
        "com.evezzon.fakegps",
        "com.gsmartstudio.fakegps",
        "com.pe.fakelocation",
        "com.lkr.fakelocation",
        "com.usefullapps.fakegpslocationpro",
        "fake.gps.location.spoofer.free",
        "com.divi.fakegps",
        "com.hola.fakegps",
        "app.fakegps.joystick",
        "com.mocklocation.gpsjoystick",
        "com.fly.gps",
        "com.jinyuan.fakegps",
        "com.sqisland.android.mocklocation"
    )

    val remoteControl = setOf(
        "com.anydesk.anydeskandroid",
        "com.anydesk.adcontrol.ad1",
        "com.teamviewer.teamviewer.market.mobile",
        "com.teamviewer.quicksupport.market",
        "com.teamviewer.host.market",
        "com.rustdesk.rustdesk",
        "com.airdroid.remote",
        "com.sand.airdroid",
        "com.sand.airsos",
        "com.koushikdutta.vysor",
        "com.splashtop.remote.pad.v2",
        "com.splashtop.sos",
        "com.gaijin.vnc",
        "com.realvnc.viewer.android",
        "com.logmein.rescuemobile",
        "net.sourceforge.vncviewer",
        "com.microsoft.rdc.androidx",
        "com.mobizen.mirroring",
        "com.aweray.deskdroid",
        "com.ammyy.admin",
        "com.zoho.assist.customer",
        "com.zoho.assist.agent"
    )

    val virtualCamera = setOf(
        "com.virtualcamera",
        "com.android.virtualcamera",
        "com.github.lsposed.vcam",
        "com.example.vcam",
        "com.wangyiheng.vcamsx",
        "com.vcam.android",
        "io.github.a13e300.vcam",
        "com.sys.virtualcamera",
        "com.nonameapps.virtualcamera",
        "com.xiaofeng.virtualcamera",
        "com.droidcam.android",
        "com.dev47apps.droidcam",
        "com.dev47apps.droidcamx",
        "com.pixel.virtualcamera",
        "com.fakecamera.android",
        "com.virtualcam.fakecamera",
        "app.virtualcam.fake",
        "com.camera.fake",
        "com.ivcam.android",
        "com.obsproject.virtualcam",
        "com.kinoni.iriunwebcam",
    )

    val cloners = setOf(
        "com.lbe.parallel.intl",
        "com.lbe.parallel",
        "com.excelliance.dualaid",
        "com.excelliance.multiaccount",
        "com.ludashi.dualspace",
        "com.polestar.super.clone",
        "io.va.exposed",
        "com.vmos.pro",
        "com.vmos.glb",
        "com.cloudphone.android",
        "com.lody.virtual",
        "com.qihoo.magic",
        "com.dualspace.app",
        "com.applisto.appcloner",
        "com.applisto.appcloner.pro",
        "info.red.virtual",
        "com.cloneapp.parallel"
    )

    /** Apps preinstalled by desktop Android emulators. */
    val emulator = setOf(
        "com.bluestacks.appmart",
        "com.bluestacks.home",
        "com.bluestacks.settings",
        "com.bluestacks.bstfolder",
        "com.bluestacks.launcher",
        "com.bignox.app",
        "com.bignox.launcher",
        "com.vphone.launcher",
        "com.ldmnq.launcher3",
        "com.android.flysilkworm",
        "com.microvirt.launcher",
        "com.microvirt.guide",
        "com.microvirt.tools",
        "com.microvirt.memuime",
        "com.genymotion.superuser",
        "com.genymotion.systempatcher",
        "com.google.android.launcher.layouts.genymotion",
        "com.mumu.launcher",
        "com.netease.mumu.cloner"
    )
}
