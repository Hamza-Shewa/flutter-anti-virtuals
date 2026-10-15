import 'dart:typed_data';

/// Which Apple servers and App Attest environment an app build uses.
///
/// Builds you run from Xcode use [development]; App Store, TestFlight and
/// Enterprise builds use [production]. Keys, receipts and DeviceCheck tokens
/// from one environment do not work in the other.
enum AppleEnvironment { production, development }

/// An App Attest key your server enrolled from an attestation, as an
/// `AppAttestKeyStore` keeps it.
final class AppAttestKey {
  AppAttestKey({
    required this.keyId,
    required Uint8List publicKey,
    required this.appId,
    required this.environment,
    this.counter = 0,
    Uint8List? receipt,
    this.attestedAt,
  }) : publicKey = Uint8List.fromList(publicKey),
       receipt = receipt == null ? null : Uint8List.fromList(receipt);

  /// The key identifier as standard base64, the way the app sends it. It is
  /// the SHA-256 of [publicKey].
  final String keyId;

  /// The uncompressed P-256 point (65 bytes) from the credential
  /// certificate.
  final Uint8List publicKey;

  /// `<TeamID>.<BundleID>` of the app that created the key.
  final String appId;

  final AppleEnvironment environment;

  /// The counter of the last accepted assertion, 0 right after the
  /// attestation.
  final int counter;

  /// The receipt from the attestation. Exchange it with
  /// `AppAttestReceiptClient` for one with a risk metric.
  final Uint8List? receipt;

  final DateTime? attestedAt;

  AppAttestKey withCounter(int counter) => AppAttestKey(
    keyId: keyId,
    publicKey: publicKey,
    appId: appId,
    environment: environment,
    counter: counter,
    receipt: receipt,
    attestedAt: attestedAt,
  );
}

/// What App Attest proved for an accepted iOS report.
final class AppAttestResult {
  const AppAttestResult({
    required this.keyId,
    required this.isNewKey,
    required this.counter,
    required this.appId,
    required this.environment,
    required this.publicKey,
    this.receipt,
    this.validationCategory,
    this.bundleVersion,
  });

  /// Base64 key identifier.
  final String keyId;

  /// True for an attestation: the key was enrolled with this request. False
  /// for an assertion with a key enrolled earlier.
  final bool isNewKey;

  /// 0 for an attestation, the assertion counter otherwise.
  final int counter;

  /// `<TeamID>.<BundleID>` whose hash the authenticator data carries.
  final String appId;

  final AppleEnvironment environment;

  /// The key's uncompressed P-256 point.
  final Uint8List publicKey;

  /// Attestation only: the receipt bytes from the attestation statement.
  final Uint8List? receipt;

  /// `apple_validation_category_01` from the authenticator data extensions,
  /// when the OS included it: how the app was distributed (2 TestFlight, 3
  /// development signed, 4 App Store, 5 Enterprise or ad hoc, see Apple's
  /// table).
  final int? validationCategory;

  /// `apple_bundle_version_01` from the authenticator data extensions, when
  /// the OS included it.
  final String? bundleVersion;
}

/// Field 6 of an App Attest receipt.
enum AppAttestReceiptType {
  /// The receipt inside an attestation. It has no risk metric.
  attest('ATTEST'),

  /// A receipt from Apple's server, with a risk metric.
  receipt('RECEIPT');

  const AppAttestReceiptType(this.value);

  /// The string in the receipt.
  final String value;

  static AppAttestReceiptType? parse(String? value) {
    for (final type in values) {
      if (type.value == value) return type;
    }
    return null;
  }
}

/// The payload of an App Attest receipt (see Apple's "Assessing fraud
/// risk"). `AppAttestReceiptReader` builds it after it checked the
/// signature.
final class AppAttestReceipt {
  AppAttestReceipt({
    required Uint8List bytes,
    required this.appId,
    required this.type,
    required this.createdAt,
    required Map<int, Uint8List> fields,
    this.attestedCertificate,
    this.attestedPublicKey,
    this.clientHash,
    this.token,
    this.riskMetric,
    this.notBefore,
    this.expiresAt,
  }) : bytes = Uint8List.fromList(bytes),
       fields = Map.unmodifiable(fields);

  /// The receipt as Apple sent it (DER/BER PKCS #7). Store it: it is what
  /// you send to refresh the metric.
  final Uint8List bytes;

  /// Field 2: `<TeamID>.<BundleID>`.
  final String appId;

  /// Field 6.
  final AppAttestReceiptType type;

  /// Field 12.
  final DateTime createdAt;

  /// Field 3: the DER credential certificate of the attested key.
  final Uint8List? attestedCertificate;

  /// The uncompressed P-256 point of [attestedCertificate].
  final Uint8List? attestedPublicKey;

  /// Field 4.
  final Uint8List? clientHash;

  /// Field 5.
  final String? token;

  /// Field 17, [AppAttestReceiptType.receipt] only: about how many keys
  /// were attested for your app on this device in the last 30 days. Expect
  /// a low number; reinstalls and restores raise it a little.
  final int? riskMetric;

  /// Field 19: do not ask for a new receipt before this time (Apple answers
  /// 304).
  final DateTime? notBefore;

  /// Field 21: ask for a new receipt before this time or Apple may refuse.
  final DateTime? expiresAt;

  /// Every field by type, as the raw octets of its value.
  final Map<int, Uint8List> fields;
}
