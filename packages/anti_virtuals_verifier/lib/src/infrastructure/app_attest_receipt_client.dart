import 'dart:convert';
import 'dart:typed_data';

import '../domain/app_attest.dart';
import '../domain/ports.dart';
import 'app_attest_receipt.dart';
import 'apple_jwt.dart';

/// Exchanges an App Attest receipt with Apple's `attestationData` endpoint
/// for a new one that carries a risk metric (see Apple's "Assessing fraud
/// risk").
///
/// Start with the receipt from the attestation (`AppAttestKey.receipt`),
/// then store each new receipt in place of the old one and send that next
/// time: after its [AppAttestReceipt.notBefore] and before its
/// [AppAttestReceipt.expiresAt].
final class AppAttestReceiptClient {
  AppAttestReceiptClient({
    required HttpTransport transport,
    required AppleJwtSigner signer,
    this.environment = AppleEnvironment.production,
    AppAttestReceiptReader? reader,
    this.maxAge = const Duration(minutes: 5),
  }) : _transport = transport,
       _signer = signer,
       _reader = reader ?? AppAttestReceiptReader();

  /// The environment the key was attested in (`AppAttestKey.environment`).
  /// A receipt from one environment does not work in the other.
  final AppleEnvironment environment;

  /// How old the new receipt's creation time may be.
  final Duration maxAge;

  final HttpTransport _transport;
  final AppleJwtSigner _signer;
  final AppAttestReceiptReader _reader;

  /// The `attestationData` endpoint of [environment].
  Uri get uri => switch (environment) {
    AppleEnvironment.production => Uri.https(
      'data.appattest.apple.com',
      '/v1/attestationData',
    ),
    AppleEnvironment.development => Uri.https(
      'data-development.appattest.apple.com',
      '/v1/attestationData',
    ),
  };

  /// Sends [receipt] and returns Apple's new receipt, after
  /// [AppAttestReceiptReader.read] verified its signature, that it is for
  /// [appId] and [publicKey] when you pass them, and that it is fresh.
  ///
  /// Returns null when Apple answers 304: the previous receipt's "not
  /// before" time has not passed, so keep using it. Throws [ApiException]
  /// for other errors (400 wrong environment or bad payload, 401 bad token,
  /// 404 no data, 429 too many requests, 5xx) and
  /// [InvalidReceiptException] when the new receipt does not verify.
  Future<AppAttestReceipt?> refresh(
    Uint8List receipt, {
    String? appId,
    Uint8List? publicKey,
  }) async {
    final response = await _transport.send(
      TransportRequest(
        method: 'POST',
        uri: uri,
        headers: {
          'authorization': _signer.token(),
          'content-type': 'application/octet-stream',
        },
        body: utf8.encode(base64.encode(receipt)),
      ),
    );
    if (response.statusCode == 304) return null;
    if (response.statusCode != 200) {
      throw ApiException(uri, response.statusCode, response.text);
    }
    final Uint8List bytes;
    try {
      bytes = base64.decode(response.text.replaceAll(RegExp(r'\s'), ''));
    } on FormatException {
      throw const InvalidReceiptException('The response is not base64');
    }
    return _reader.read(
      bytes,
      appId: appId,
      publicKey: publicKey,
      maxAge: maxAge,
    );
  }
}
