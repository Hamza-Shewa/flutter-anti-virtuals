import 'dart:ui' show Locale, TextDirection;

import '../signal.dart';

/// User-facing text for the default blocking screen. Pass your own instance to
/// [AntiVirtualGuard.messages] to replace or translate any string.
class AntiVirtualMessages {
  const AntiVirtualMessages({
    required this.title,
    required this.subtitle,
    required this.closingIn,
    required this.signals,
    this.textDirection = TextDirection.ltr,
  });

  /// Languages shipped with the package.
  static List<String> get supportedLanguages =>
      List<String>.unmodifiable(_byLanguage.keys);

  final String title;
  final String subtitle;

  /// Builds the "the app will close in N seconds" line. A function so each
  /// language can apply its own plural rules.
  final String Function(int seconds) closingIn;

  /// Layout direction of the language these messages are written in.
  final TextDirection textDirection;

  /// One message per signal. A missing signal falls back to its enum name.
  final Map<AntiVirtualSignal, String> signals;

  String messageFor(AntiVirtualSignal signal) => signals[signal] ?? signal.name;

  String closingMessage(int seconds) => closingIn(seconds);

  /// Messages for [locale], falling back to English.
  static AntiVirtualMessages forLocale(Locale? locale) =>
      _byLanguage[locale?.languageCode] ?? english;

  AntiVirtualMessages copyWith({
    String? title,
    String? subtitle,
    String Function(int seconds)? closingIn,
    Map<AntiVirtualSignal, String>? signals,
    TextDirection? textDirection,
  }) => AntiVirtualMessages(
    title: title ?? this.title,
    subtitle: subtitle ?? this.subtitle,
    closingIn: closingIn ?? this.closingIn,
    signals: <AntiVirtualSignal, String>{...this.signals, ...?signals},
  );

  static const AntiVirtualMessages english = AntiVirtualMessages(
    title: 'This device can\'t be verified',
    subtitle: 'Please resolve the following and try again:',
    closingIn: _closingEnglish,
    signals: <AntiVirtualSignal, String>{
      AntiVirtualSignal.vpn: 'A VPN is active. Turn it off to continue.',
      AntiVirtualSignal.proxy:
          'A network proxy is configured. Remove it to continue.',
      AntiVirtualSignal.mockLocation: 'Fake GPS or a mock-location app was detected. Turn it off to continue.',
      AntiVirtualSignal.virtualCamera:
          'A virtual or external camera was detected. Disable it to continue.',
      AntiVirtualSignal.developerOptions: 'Developer options are turned on.',
      AntiVirtualSignal.adb: 'USB or wireless debugging is turned on.',
      AntiVirtualSignal.clockTampering: 'The device date, time or time zone looks incorrect. Enable automatic date & time.',
      AntiVirtualSignal.untrustedInstaller: 'This app was not installed from a trusted store. Install it from the official store.',
      AntiVirtualSignal.signatureMismatch: 'This app has been modified or re-signed. Install the official version.',
      AntiVirtualSignal.accessibilityAbuse:
          'An accessibility service that can read your screen is active.',
      AntiVirtualSignal.remoteControlApp:
          'A remote-control app is installed. Remove it to continue.',
      AntiVirtualSignal.clonedApp:
          'The app is running in a cloned or parallel space.',
      AntiVirtualSignal.userCertificates:
          'A user-installed security certificate was detected.',
      AntiVirtualSignal.sideloaded:
          'This app was installed outside the App Store.',
    },
  );

  static const AntiVirtualMessages arabic = AntiVirtualMessages(
    title: 'لا يمكن التحقق من هذا الجهاز',
    subtitle: 'يرجى معالجة ما يلي ثم المحاولة مرة أخرى:',
    closingIn: _closingArabic,
    textDirection: TextDirection.rtl,
    signals: <AntiVirtualSignal, String>{
      AntiVirtualSignal.vpn: 'شبكة VPN نشطة. أوقفها للمتابعة.',
      AntiVirtualSignal.proxy: 'تم إعداد وكيل (Proxy) للشبكة. أزله للمتابعة.',
      AntiVirtualSignal.mockLocation:
          'تم اكتشاف موقع وهمي أو تطبيق لتزييف الموقع. أوقفه للمتابعة.',
      AntiVirtualSignal.virtualCamera:
          'تم اكتشاف كاميرا افتراضية أو خارجية. عطّلها للمتابعة.',
      AntiVirtualSignal.developerOptions: 'خيارات المطوّر مفعّلة.',
      AntiVirtualSignal.adb: 'تصحيح أخطاء USB أو اللاسلكي مفعّل.',
      AntiVirtualSignal.clockTampering: 'تاريخ الجهاز أو وقته أو منطقته الزمنية غير صحيحة. فعّل التاريخ والوقت التلقائيين.',
      AntiVirtualSignal.untrustedInstaller:
          'لم يتم تثبيت هذا التطبيق من متجر موثوق. ثبّته من المتجر الرسمي.',
      AntiVirtualSignal.signatureMismatch:
          'تم تعديل هذا التطبيق أو إعادة توقيعه. ثبّت النسخة الرسمية.',
      AntiVirtualSignal.accessibilityAbuse:
          'خدمة وصول نشطة قادرة على قراءة شاشتك.',
      AntiVirtualSignal.remoteControlApp:
          'تم تثبيت تطبيق تحكم عن بُعد. أزله للمتابعة.',
      AntiVirtualSignal.clonedApp: 'التطبيق يعمل داخل مساحة مستنسخة أو موازية.',
      AntiVirtualSignal.userCertificates:
          'تم اكتشاف شهادة أمان مثبّتة من المستخدم.',
      AntiVirtualSignal.sideloaded: 'تم تثبيت هذا التطبيق من خارج App Store.',
    },
  );

  static const AntiVirtualMessages french = AntiVirtualMessages(
    title: 'Cet appareil ne peut pas être vérifié',
    subtitle: 'Veuillez corriger les points suivants puis réessayer :',
    closingIn: _closingFrench,
    signals: <AntiVirtualSignal, String>{
      AntiVirtualSignal.vpn: 'Un VPN est actif. Désactivez-le pour continuer.',
      AntiVirtualSignal.proxy:
          'Un proxy réseau est configuré. Supprimez-le pour continuer.',
      AntiVirtualSignal.mockLocation: 'Une fausse position GPS ou une application de simulation a été détectée. Désactivez-la pour continuer.',
      AntiVirtualSignal.virtualCamera: 'Une caméra virtuelle ou externe a été détectée. Désactivez-la pour continuer.',
      AntiVirtualSignal.developerOptions:
          'Les options pour les développeurs sont activées.',
      AntiVirtualSignal.adb: 'Le débogage USB ou sans fil est activé.',
      AntiVirtualSignal.clockTampering: 'La date, l\'heure ou le fuseau horaire de l\'appareil semble incorrect. Activez la date et l\'heure automatiques.',
      AntiVirtualSignal.untrustedInstaller: 'Cette application n\'a pas été installée depuis une boutique de confiance. Installez-la depuis la boutique officielle.',
      AntiVirtualSignal.signatureMismatch: 'Cette application a été modifiée ou re-signée. Installez la version officielle.',
      AntiVirtualSignal.accessibilityAbuse:
          'Un service d\'accessibilité capable de lire votre écran est actif.',
      AntiVirtualSignal.remoteControlApp: 'Une application de contrôle à distance est installée. Désinstallez-la pour continuer.',
      AntiVirtualSignal.clonedApp:
          'L\'application s\'exécute dans un espace cloné ou parallèle.',
      AntiVirtualSignal.userCertificates: 'Un certificat de sécurité installé par l\'utilisateur a été détecté.',
      AntiVirtualSignal.sideloaded:
          'Cette application a été installée en dehors de l\'App Store.',
    },
  );

  static const AntiVirtualMessages spanish = AntiVirtualMessages(
    title: 'No se puede verificar este dispositivo',
    subtitle: 'Soluciona lo siguiente e inténtalo de nuevo:',
    closingIn: _closingSpanish,
    signals: <AntiVirtualSignal, String>{
      AntiVirtualSignal.vpn: 'Hay una VPN activa. Desactívala para continuar.',
      AntiVirtualSignal.proxy:
          'Hay un proxy de red configurado. Elimínalo para continuar.',
      AntiVirtualSignal.mockLocation: 'Se detectó una ubicación GPS falsa o una aplicación de simulación. Desactívala para continuar.',
      AntiVirtualSignal.virtualCamera: 'Se detectó una cámara virtual o externa. Desactívala para continuar.',
      AntiVirtualSignal.developerOptions:
          'Las opciones de desarrollador están activadas.',
      AntiVirtualSignal.adb: 'La depuración USB o inalámbrica está activada.',
      AntiVirtualSignal.clockTampering: 'La fecha, la hora o la zona horaria del dispositivo parece incorrecta. Activa la fecha y hora automáticas.',
      AntiVirtualSignal.untrustedInstaller: 'Esta aplicación no se instaló desde una tienda de confianza. Instálala desde la tienda oficial.',
      AntiVirtualSignal.signatureMismatch: 'Esta aplicación fue modificada o firmada de nuevo. Instala la versión oficial.',
      AntiVirtualSignal.accessibilityAbuse:
          'Hay un servicio de accesibilidad activo que puede leer tu pantalla.',
      AntiVirtualSignal.remoteControlApp: 'Hay una aplicación de control remoto instalada. Desinstálala para continuar.',
      AntiVirtualSignal.clonedApp:
          'La aplicación se ejecuta en un espacio clonado o paralelo.',
      AntiVirtualSignal.userCertificates:
          'Se detectó un certificado de seguridad instalado por el usuario.',
      AntiVirtualSignal.sideloaded:
          'Esta aplicación se instaló fuera de la App Store.',
    },
  );

  static const Map<String, AntiVirtualMessages> _byLanguage =
      <String, AntiVirtualMessages>{
        'en': english,
        'ar': arabic,
        'fr': french,
        'es': spanish,
      };
}

String _closingEnglish(int n) => n == 1
    ? 'The app will close in 1 second.'
    : 'The app will close in $n seconds.';

// French treats 0 and 1 as singular.
String _closingFrench(int n) => n <= 1
    ? "L'application se fermera dans $n seconde."
    : "L'application se fermera dans $n secondes.";

String _closingSpanish(int n) => n == 1
    ? 'La aplicación se cerrará en 1 segundo.'
    : 'La aplicación se cerrará en $n segundos.';

// Arabic has distinct forms for 1, 2, 3-10 and 11+ (0 and 100+ ignored here).
String _closingArabic(int n) {
  final unit = switch (n) {
    1 => 'ثانية واحدة',
    2 => 'ثانيتين',
    >= 3 && <= 10 => '$n ثوانٍ',
    _ => '$n ثانية',
  };
  return 'سيُغلق التطبيق خلال $unit.';
}
