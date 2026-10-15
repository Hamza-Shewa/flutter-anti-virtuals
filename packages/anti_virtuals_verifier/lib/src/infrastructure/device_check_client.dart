import 'dart:convert';
import 'dart:math';

import '../domain/app_attest.dart';
import '../domain/device_check.dart';
import '../domain/ports.dart';
import 'apple_jwt.dart';

/// Reads and sets the two bits Apple keeps per device for your team, with
/// the `deviceCheckToken` the app sends when it calls `verify` with
/// `AttestationOptions(deviceCheck: true)`.
///
/// The bits survive a reinstall and an app data reset; use them for things
/// like "already claimed the trial". Apple validates the token: it proves
/// the request comes from an Apple device running an app of your team. It is
/// not bound to the signed payload, so it does not prove which device sent
/// the report.
final class DeviceCheckClient {
  DeviceCheckClient({
    required HttpTransport transport,
    required AppleJwtSigner signer,
    this.environment = AppleEnvironment.production,
    DateTime Function()? clock,
    String Function()? transactionIds,
  }) : _transport = transport,
       _signer = signer,
       _clock = clock ?? DateTime.now,
       _transactionIds = transactionIds ?? _uuid;

  /// [AppleEnvironment.development] for builds run from Xcode, whose tokens
  /// only the development server accepts.
  final AppleEnvironment environment;

  final HttpTransport _transport;
  final AppleJwtSigner _signer;
  final DateTime Function() _clock;
  final String Function() _transactionIds;

  static final _random = Random.secure();

  Uri get _base => switch (environment) {
    AppleEnvironment.production => Uri.https('api.devicecheck.apple.com'),
    AppleEnvironment.development => Uri.https(
      'api.development.devicecheck.apple.com',
    ),
  };

  /// The device's bits, or null when Apple has none for it yet ("Bit State
  /// Not Found"). Throws [ApiException] on any other answer.
  Future<DeviceCheckBits?> queryTwoBits(String deviceToken) async {
    final response = await _post('query_two_bits', deviceToken);
    final text = response.text.trim();
    if (text.toLowerCase().contains('bit state not found')) return null;
    final Object? json;
    try {
      json = jsonDecode(text);
    } on FormatException {
      throw ApiException(_base.resolve('/v1/query_two_bits'), 200, text);
    }
    if (json is! Map<String, Object?>) {
      throw ApiException(_base.resolve('/v1/query_two_bits'), 200, text);
    }
    return DeviceCheckBits(
      bit0: json['bit0'] == true,
      bit1: json['bit1'] == true,
      lastUpdateTime: switch (json['last_update_time']) {
        final String time => time,
        _ => null,
      },
    );
  }

  /// Sets the bits you pass; a null bit keeps its value. Throws
  /// [ApiException] when Apple refuses.
  Future<void> updateTwoBits(
    String deviceToken, {
    bool? bit0,
    bool? bit1,
  }) async {
    if (bit0 == null && bit1 == null) {
      throw ArgumentError('Set bit0, bit1 or both');
    }
    await _post('update_two_bits', deviceToken, {'bit0': ?bit0, 'bit1': ?bit1});
  }

  /// Asks Apple whether [deviceToken] is valid. Returns normally when it
  /// is, throws [ApiException] (for example 400 "Bad Device Token") when it
  /// is not.
  Future<void> validateDeviceToken(String deviceToken) async {
    await _post('validate_device_token', deviceToken);
  }

  Future<TransportResponse> _post(
    String endpoint,
    String deviceToken, [
    Map<String, Object?> extra = const {},
  ]) async {
    final uri = _base.resolve('/v1/$endpoint');
    final response = await _transport.send(
      TransportRequest(
        method: 'POST',
        uri: uri,
        headers: {
          'authorization': 'Bearer ${_signer.token()}',
          'content-type': 'application/json',
        },
        body: utf8.encode(
          jsonEncode({
            'device_token': deviceToken.replaceAll(RegExp(r'\s'), ''),
            'transaction_id': _transactionIds(),
            'timestamp': _clock().millisecondsSinceEpoch,
            ...extra,
          }),
        ),
      ),
    );
    if (response.statusCode != 200) {
      throw ApiException(uri, response.statusCode, response.text);
    }
    return response;
  }

  /// A random version 4 UUID.
  static String _uuid() {
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
        '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
  }
}
