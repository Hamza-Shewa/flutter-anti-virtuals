import 'dart:convert';

/// A value Google sends as a string, such as `PLAY_RECOGNIZED`.
abstract interface class GoogleValue {
  /// The exact string in Google's JSON.
  String get value;
}

T? _parse<T extends GoogleValue>(List<T> values, Object? raw) {
  for (final value in values) {
    if (value.value == raw) return value;
  }
  return null;
}

Set<T> _parseAll<T extends GoogleValue>(List<T> values, Object? raw) => {
  if (raw is List)
    for (final item in raw) ?_parse(values, item),
};

/// `appIntegrity.appRecognitionVerdict`.
enum AppRecognitionVerdict implements GoogleValue {
  /// The app and certificate match the versions Google Play distributes.
  playRecognized('PLAY_RECOGNIZED'),

  /// The certificate or package name does not match Google Play's records.
  unrecognizedVersion('UNRECOGNIZED_VERSION'),

  /// Not evaluated, for example because the device is not trustworthy enough.
  unevaluated('UNEVALUATED'),
  unknown('UNKNOWN');

  const AppRecognitionVerdict(this.value);

  @override
  final String value;

  static AppRecognitionVerdict? parse(Object? value) => _parse(values, value);
}

/// A label of `deviceIntegrity.deviceRecognitionVerdict`.
enum DeviceRecognitionLabel implements GoogleValue {
  /// Passes basic system integrity checks; the bootloader may be unlocked.
  /// Optional label you opt in to in the Play Console.
  meetsBasicIntegrity('MEETS_BASIC_INTEGRITY'),

  /// A genuine, certified Android device.
  meetsDeviceIntegrity('MEETS_DEVICE_INTEGRITY'),

  /// A genuine, certified device with a recent security update (Android 13
  /// and higher). Optional label you opt in to in the Play Console.
  meetsStrongIntegrity('MEETS_STRONG_INTEGRITY'),

  /// An Android emulator with Google Play services that passes integrity
  /// checks (Google Play Games for PC).
  meetsVirtualIntegrity('MEETS_VIRTUAL_INTEGRITY');

  const DeviceRecognitionLabel(this.value);

  @override
  final String value;

  static DeviceRecognitionLabel? parse(Object? value) => _parse(values, value);
}

/// `accountDetails.appLicensingVerdict`.
enum AppLicensingVerdict implements GoogleValue {
  /// The user installed or bought the app from Google Play.
  licensed('LICENSED'),

  /// The user has no entitlement, for example after sideloading the app.
  unlicensed('UNLICENSED'),

  /// Not evaluated: the device is not trustworthy enough, the app version is
  /// unknown to Play, or the user is not signed in.
  unevaluated('UNEVALUATED'),
  unknown('UNKNOWN');

  const AppLicensingVerdict(this.value);

  @override
  final String value;

  static AppLicensingVerdict? parse(Object? value) => _parse(values, value);
}

/// `deviceIntegrity.recentDeviceActivity.deviceActivityLevel`: how many
/// integrity tokens your app requested on this device in the last hour.
enum DeviceActivityLevel implements GoogleValue {
  /// Standard requests: 10 or fewer. Classic requests: 5 or fewer.
  level1('LEVEL_1'),

  /// Standard: 11 to 25. Classic: 6 to 10.
  level2('LEVEL_2'),

  /// Standard: 26 to 50. Classic: 11 to 15.
  level3('LEVEL_3'),

  /// Standard: more than 50. Classic: more than 15.
  level4('LEVEL_4'),

  /// Not evaluated, for example because the device is not trustworthy
  /// enough or the app is not licensed.
  unevaluated('UNEVALUATED');

  const DeviceActivityLevel(this.value);

  @override
  final String value;

  /// True for a level at or below [cap]. Always false for [unevaluated] on
  /// either side.
  bool isAtMost(DeviceActivityLevel cap) =>
      this != unevaluated && cap != unevaluated && index <= cap.index;

  static DeviceActivityLevel? parse(Object? value) => _parse(values, value);
}

/// A response in `environmentDetails.appAccessRiskVerdict.appsDetected`.
///
/// `KNOWN_` responses are about apps installed by Google Play or preloaded on
/// the system partition, `UNKNOWN_` responses about all other apps.
enum AppAccessRisk implements GoogleValue {
  knownInstalled('KNOWN_INSTALLED'),

  /// A known app is running that could view the screen.
  knownCapturing('KNOWN_CAPTURING'),

  /// A known app is running that could control the device and its inputs.
  knownControlling('KNOWN_CONTROLLING'),

  /// A known app is running that could draw overlays on your app.
  knownOverlays('KNOWN_OVERLAYS'),
  unknownInstalled('UNKNOWN_INSTALLED'),
  unknownCapturing('UNKNOWN_CAPTURING'),
  unknownControlling('UNKNOWN_CONTROLLING'),
  unknownOverlays('UNKNOWN_OVERLAYS');

  const AppAccessRisk(this.value);

  @override
  final String value;

  /// Unknown apps that could capture the screen or control the device: what
  /// the `CLOSE_UNKNOWN_ACCESS_RISK` dialog asks the user to close.
  static const unknownCapturingOrControlling = {
    unknownCapturing,
    unknownControlling,
  };

  /// Any app that could capture the screen or control the device: what the
  /// `CLOSE_ALL_ACCESS_RISK` dialog asks the user to close.
  static const capturingOrControlling = {
    knownCapturing,
    knownControlling,
    unknownCapturing,
    unknownControlling,
  };

  static AppAccessRisk? parse(Object? value) => _parse(values, value);
}

/// `environmentDetails.playProtectVerdict`.
enum PlayProtectVerdict implements GoogleValue {
  /// Play Protect is on and found no issues.
  noIssues('NO_ISSUES'),

  /// Play Protect is on but has not scanned yet.
  noData('NO_DATA'),

  /// Play Protect is turned off.
  possibleRisk('POSSIBLE_RISK'),

  /// Play Protect found potentially harmful apps.
  mediumRisk('MEDIUM_RISK'),

  /// Play Protect found dangerous apps.
  highRisk('HIGH_RISK'),

  /// Not evaluated, for example because the device is not trustworthy enough.
  unevaluated('UNEVALUATED');

  const PlayProtectVerdict(this.value);

  @override
  final String value;

  static PlayProtectVerdict? parse(Object? value) => _parse(values, value);
}

/// A Google Play dialog the app can show to fix what made a verdict fail.
///
/// The names match the plugin's `PlayIntegrityDialog`, so a server can send
/// [name] to the app, which shows the dialog with
/// `showPlayIntegrityDialog(PlayIntegrityDialog.values.byName(name))`.
enum PlayIntegrityRemediation {
  /// `GET_LICENSED`: the app is not licensed or not the version Play
  /// distributes.
  getLicensed(1),

  /// `CLOSE_UNKNOWN_ACCESS_RISK`: unknown apps could capture the screen or
  /// control the device.
  closeUnknownAccessRisk(2),

  /// `CLOSE_ALL_ACCESS_RISK`: known or unknown apps could capture the screen
  /// or control the device.
  closeAllAccessRisk(3),

  /// `GET_INTEGRITY`: device integrity, licensing or app integrity issues.
  getIntegrity(4),

  /// `GET_STRONG_INTEGRITY`: like [getIntegrity], and also strong integrity
  /// and Play Protect issues.
  getStrongIntegrity(5);

  const PlayIntegrityRemediation(this.typeCode);

  /// Google's `IntegrityDialogTypeCode`.
  final int typeCode;
}

/// `requestDetails`: what the app asked for.
final class RequestDetails {
  const RequestDetails({
    this.requestPackageName,
    this.nonce,
    this.requestHash,
    this.timestampMillis,
  });

  factory RequestDetails.fromJson(Map<String, Object?> json) => RequestDetails(
    requestPackageName: _string(json['requestPackageName']),
    nonce: _string(json['nonce']),
    requestHash: _string(json['requestHash']),
    timestampMillis: _int(json['timestampMillis']),
  );

  /// The package the token was requested for. Not proof of the caller; see
  /// [AppIntegrity] for that.
  final String? requestPackageName;

  /// Classic requests: the nonce the app passed (URL-safe base64).
  final String? nonce;

  /// Standard requests: the request hash the app passed.
  final String? requestHash;

  final int? timestampMillis;

  /// When the token was requested.
  DateTime? get timestamp => timestampMillis == null
      ? null
      : DateTime.fromMillisecondsSinceEpoch(timestampMillis!, isUtc: true);
}

/// `appIntegrity`: whether Play knows this build of the app.
final class AppIntegrity {
  const AppIntegrity({
    this.appRecognitionVerdict,
    this.packageName,
    this.certificateSha256Digest = const [],
    this.versionCode,
  });

  factory AppIntegrity.fromJson(Map<String, Object?> json) => AppIntegrity(
    appRecognitionVerdict: AppRecognitionVerdict.parse(
      json['appRecognitionVerdict'],
    ),
    packageName: _string(json['packageName']),
    certificateSha256Digest: List.unmodifiable([
      for (final digest in json['certificateSha256Digest'] as List? ?? const [])
        if (digest is String) digest,
    ]),
    versionCode: _int(json['versionCode']),
  );

  final AppRecognitionVerdict? appRecognitionVerdict;
  final String? packageName;

  /// SHA-256 of the app's signing certificates, URL-safe base64 as Google
  /// sends them.
  final List<String> certificateSha256Digest;

  final int? versionCode;

  /// [certificateSha256Digest] as lowercase hex. Entries that are not valid
  /// base64 are left out.
  Set<String> get certificateSha256Hex => {
    for (final digest in certificateSha256Digest)
      if (_base64Url(digest) case final bytes?)
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
  };
}

/// `deviceIntegrity.deviceRecall.values`: three bits you store per device
/// with Google. Also what you write with
/// `PlayIntegrityClient.writeDeviceRecall`, where a null bit stays unchanged.
final class DeviceRecallValues {
  const DeviceRecallValues({this.bitFirst, this.bitSecond, this.bitThird});

  factory DeviceRecallValues.fromJson(Map<String, Object?> json) =>
      DeviceRecallValues(
        bitFirst: _bool(json['bitFirst']),
        bitSecond: _bool(json['bitSecond']),
        bitThird: _bool(json['bitThird']),
      );

  final bool? bitFirst;
  final bool? bitSecond;
  final bool? bitThird;

  bool get isEmpty => bitFirst == null && bitSecond == null && bitThird == null;

  /// Google's JSON, without the bits that are null.
  Map<String, Object?> toJson() => {
    'bitFirst': ?bitFirst,
    'bitSecond': ?bitSecond,
    'bitThird': ?bitThird,
  };
}

/// `deviceIntegrity.deviceRecall.writeDates`: when each bit was last set to
/// true, as `YYYYMM` in UTC. A bit that is false has no date.
final class DeviceRecallWriteDates {
  const DeviceRecallWriteDates({
    this.yyyymmFirst,
    this.yyyymmSecond,
    this.yyyymmThird,
  });

  factory DeviceRecallWriteDates.fromJson(Map<String, Object?> json) =>
      DeviceRecallWriteDates(
        yyyymmFirst: _int(json['yyyymmFirst']),
        yyyymmSecond: _int(json['yyyymmSecond']),
        yyyymmThird: _int(json['yyyymmThird']),
      );

  final int? yyyymmFirst;
  final int? yyyymmSecond;
  final int? yyyymmThird;
}

/// `deviceIntegrity.deviceRecall` (beta): the bits you stored for this
/// device, which survive a reinstall and a factory reset.
final class DeviceRecall {
  const DeviceRecall({
    this.values = const DeviceRecallValues(),
    this.writeDates = const DeviceRecallWriteDates(),
  });

  factory DeviceRecall.fromJson(Map<String, Object?> json) => DeviceRecall(
    values: DeviceRecallValues.fromJson(_map(json['values'])),
    writeDates: DeviceRecallWriteDates.fromJson(_map(json['writeDates'])),
  );

  final DeviceRecallValues values;
  final DeviceRecallWriteDates writeDates;
}

/// `deviceIntegrity`: how well the device can enforce app integrity.
final class DeviceIntegrity {
  const DeviceIntegrity({
    this.deviceRecognitionVerdict = const {},
    this.deviceActivityLevel,
    this.sdkVersion,
    this.deviceRecall,
  });

  factory DeviceIntegrity.fromJson(Map<String, Object?> json) =>
      DeviceIntegrity(
        deviceRecognitionVerdict: Set.unmodifiable(
          _parseAll(
            DeviceRecognitionLabel.values,
            json['deviceRecognitionVerdict'],
          ),
        ),
        deviceActivityLevel: DeviceActivityLevel.parse(
          _map(json['recentDeviceActivity'])['deviceActivityLevel'],
        ),
        sdkVersion: _int(_map(json['deviceAttributes'])['sdkVersion']),
        deviceRecall: json['deviceRecall'] is Map<String, Object?>
            ? DeviceRecall.fromJson(_map(json['deviceRecall']))
            : null,
      );

  /// The labels the device meets. Empty for a device with signs of attack
  /// or compromise.
  final Set<DeviceRecognitionLabel> deviceRecognitionVerdict;

  /// `recentDeviceActivity.deviceActivityLevel`, when you opted in.
  final DeviceActivityLevel? deviceActivityLevel;

  /// `deviceAttributes.sdkVersion`, when you opted in and Play evaluated it,
  /// for example 33 for Android 13.
  final int? sdkVersion;

  /// When you opted in to device recall.
  final DeviceRecall? deviceRecall;
}

/// `accountDetails`.
final class AccountDetails {
  const AccountDetails({this.appLicensingVerdict});

  factory AccountDetails.fromJson(Map<String, Object?> json) => AccountDetails(
    appLicensingVerdict: AppLicensingVerdict.parse(json['appLicensingVerdict']),
  );

  final AppLicensingVerdict? appLicensingVerdict;
}

/// `environmentDetails`: other apps and Play Protect, when you opted in.
final class EnvironmentDetails {
  const EnvironmentDetails({this.appsDetected, this.playProtectVerdict});

  factory EnvironmentDetails.fromJson(Map<String, Object?> json) {
    final risk = _map(json['appAccessRiskVerdict']);
    return EnvironmentDetails(
      appsDetected: risk['appsDetected'] is List
          ? Set.unmodifiable(
              _parseAll(AppAccessRisk.values, risk['appsDetected']),
            )
          : null,
      playProtectVerdict: PlayProtectVerdict.parse(json['playProtectVerdict']),
    );
  }

  /// `appAccessRiskVerdict.appsDetected`. Null when app access risk was not
  /// evaluated or you did not opt in.
  final Set<AppAccessRisk>? appsDetected;

  final PlayProtectVerdict? playProtectVerdict;
}

/// A decoded Play Integrity token: the `tokenPayloadExternal` that Google's
/// `decodeIntegrityToken` returns.
final class PlayIntegrityVerdict {
  const PlayIntegrityVerdict({
    this.requestDetails = const RequestDetails(),
    this.appIntegrity = const AppIntegrity(),
    this.deviceIntegrity = const DeviceIntegrity(),
    this.accountDetails = const AccountDetails(),
    this.environmentDetails = const EnvironmentDetails(),
    this.isTestingResponse = false,
    this.json = const {},
  });

  /// Reads `tokenPayloadExternal`. A missing section, a field of an
  /// unexpected type or a value this package does not know is read as
  /// absent, which the checks treat as not meeting a requirement.
  factory PlayIntegrityVerdict.fromJson(Map<String, Object?> json) =>
      PlayIntegrityVerdict(
        requestDetails: RequestDetails.fromJson(_map(json['requestDetails'])),
        appIntegrity: AppIntegrity.fromJson(_map(json['appIntegrity'])),
        deviceIntegrity: DeviceIntegrity.fromJson(
          _map(json['deviceIntegrity']),
        ),
        accountDetails: AccountDetails.fromJson(_map(json['accountDetails'])),
        environmentDetails: EnvironmentDetails.fromJson(
          _map(json['environmentDetails']),
        ),
        isTestingResponse:
            _map(json['testingDetails'])['isTestingResponse'] == true,
        json: json,
      );

  final RequestDetails requestDetails;
  final AppIntegrity appIntegrity;
  final DeviceIntegrity deviceIntegrity;
  final AccountDetails accountDetails;
  final EnvironmentDetails environmentDetails;

  /// `testingDetails.isTestingResponse`: a response you configured for
  /// testers in the Play Console, not a real evaluation.
  final bool isTestingResponse;

  /// The JSON it was read from, for fields this class does not model.
  final Map<String, Object?> json;
}

Map<String, Object?> _map(Object? value) =>
    value is Map<String, Object?> ? value : const {};

String? _string(Object? value) => value is String ? value : null;

bool? _bool(Object? value) => value is bool ? value : null;

/// Google sends int64 values as strings and int32 values as numbers.
int? _int(Object? value) => switch (value) {
  final int number => number,
  final String text => int.tryParse(text),
  _ => null,
};

List<int>? _base64Url(String value) {
  try {
    return base64Url.decode(base64Url.normalize(value));
  } on FormatException {
    return null;
  }
}
