import 'dart:async';
import 'dart:convert';

import '../domain/play_integrity.dart';
import '../domain/ports.dart';

/// Calls the Play Integrity API (`playintegrity.googleapis.com`) for your
/// server: decodes tokens and writes device recall bits.
///
/// Authentication is yours: [accessToken] returns an OAuth 2.0 access token
/// for a service account with the `https://www.googleapis.com/auth/playintegrity`
/// scope, linked to the Google Cloud project of your app (for example from
/// `package:googleapis_auth`). It is called before every request, so it can
/// refresh the token.
final class PlayIntegrityClient {
  PlayIntegrityClient({
    required HttpTransport transport,
    required FutureOr<String> Function() accessToken,
    Uri? baseUri,
  }) : _transport = transport,
       _accessToken = accessToken,
       _base = baseUri ?? Uri.https('playintegrity.googleapis.com');

  final HttpTransport _transport;
  final FutureOr<String> Function() _accessToken;
  final Uri _base;

  static final _packageName = RegExp(r'^[A-Za-z0-9_.]+$');

  /// `v1/{packageName}:decodeIntegrityToken`. Returns the
  /// `tokenPayloadExternal` to pass to `SignedReportVerifier.verify` as
  /// `playIntegrityVerdict`. Throws [ApiException] when Google refuses.
  Future<Map<String, Object?>> decodeIntegrityToken({
    required String packageName,
    required String integrityToken,
  }) async {
    final path = 'v1/${_checked(packageName)}:decodeIntegrityToken';
    final json = await _post(path, {'integrityToken': integrityToken});
    final payload = json['tokenPayloadExternal'];
    if (payload is! Map<String, Object?>) {
      throw ApiException(_base.resolve(path), 200, jsonEncode(json));
    }
    return payload;
  }

  /// `v1/{packageName}/deviceRecall:write` (beta, early access): sets the
  /// recall bits of the device that produced [integrityToken] to
  /// [newValues]. A null bit keeps its value; setting a bit to true also
  /// sets its write date, setting it to false clears the date.
  ///
  /// Verify the token first (binding, current recall values). It stays
  /// usable for writes for 14 days. Google returns an error when device
  /// recall was not evaluated for the token, for example for an unlicensed
  /// user. Throws [ApiException] when Google refuses.
  Future<void> writeDeviceRecall({
    required String packageName,
    required String integrityToken,
    required DeviceRecallValues newValues,
  }) async {
    if (newValues.isEmpty) throw ArgumentError('Set at least one bit');
    await _post('v1/${_checked(packageName)}/deviceRecall:write', {
      'integrityToken': integrityToken,
      'newValues': newValues.toJson(),
    });
  }

  String _checked(String packageName) {
    if (!_packageName.hasMatch(packageName)) {
      throw ArgumentError.value(packageName, 'packageName');
    }
    return packageName;
  }

  Future<Map<String, Object?>> _post(
    String path,
    Map<String, Object?> body,
  ) async {
    final uri = _base.resolve(path);
    final response = await _transport.send(
      TransportRequest(
        method: 'POST',
        uri: uri,
        headers: {
          'authorization': 'Bearer ${await _accessToken()}',
          'content-type': 'application/json',
        },
        body: utf8.encode(jsonEncode(body)),
      ),
    );
    if (response.statusCode != 200) {
      throw ApiException(uri, response.statusCode, response.text);
    }
    final text = response.text.trim();
    if (text.isEmpty) return const {};
    final Object? json;
    try {
      json = jsonDecode(text);
    } on FormatException {
      throw ApiException(uri, response.statusCode, text);
    }
    if (json is! Map<String, Object?>) {
      throw ApiException(uri, response.statusCode, text);
    }
    return json;
  }
}
