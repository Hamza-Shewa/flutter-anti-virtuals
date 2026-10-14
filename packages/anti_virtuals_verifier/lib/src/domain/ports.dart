import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'app_attest.dart';

/// Your nonce storage, for example Redis or a database table.
abstract interface class NonceStore {
  /// Returns true exactly once for a nonce this server issued that has not
  /// expired, and consumes it. Must be atomic: two concurrent calls with the
  /// same nonce may not both return true.
  FutureOr<bool> consume(String nonce);
}

/// Revoked attestation certificates, from Google's status list.
abstract interface class RevocationList {
  bool isRevoked(BigInt serialNumber);
}

/// Your storage for enrolled App Attest keys, for example a database table
/// keyed by key id.
abstract interface class AppAttestKeyStore {
  /// The key enrolled under [keyId], or null.
  FutureOr<AppAttestKey?> find(String keyId);

  /// Stores a newly attested key. Returns false, and changes nothing, when
  /// a key with the same id is already stored.
  FutureOr<bool> save(AppAttestKey key);

  /// Sets the counter of [keyId] to [next] only if it is still [expected],
  /// and returns whether it did. Must be atomic (for example
  /// `UPDATE ... SET counter = next WHERE key_id = ? AND counter = expected`),
  /// so that two requests with the same assertion cannot both pass.
  FutureOr<bool> compareAndSetCounter(
    String keyId, {
    required int expected,
    required int next,
  });
}

/// An HTTP request to Apple or Google.
final class TransportRequest {
  TransportRequest({
    required this.method,
    required this.uri,
    this.headers = const {},
    List<int> body = const [],
  }) : body = Uint8List.fromList(body);

  final String method;
  final Uri uri;
  final Map<String, String> headers;
  final Uint8List body;

  /// The body as UTF-8 text.
  String get text => utf8.decode(body, allowMalformed: true);
}

/// The answer to a [TransportRequest].
final class TransportResponse {
  TransportResponse({
    required this.statusCode,
    List<int> body = const [],
    this.headers = const {},
  }) : body = Uint8List.fromList(body);

  final int statusCode;
  final Uint8List body;

  /// Header names in lowercase.
  final Map<String, String> headers;

  /// The body as UTF-8 text.
  String get text => utf8.decode(body, allowMalformed: true);
}

/// Sends HTTP requests. `IoHttpTransport` does it with `dart:io`; tests and
/// apps with their own HTTP stack can implement it.
abstract interface class HttpTransport {
  Future<TransportResponse> send(TransportRequest request);
}

/// Apple or Google answered with an unexpected status or body.
final class ApiException implements Exception {
  const ApiException(this.uri, this.statusCode, this.body);

  final Uri uri;
  final int statusCode;

  /// The response body, for logs. Apple sends a short reason such as
  /// `Bad Device Token`; Google sends a JSON error object.
  final String body;

  @override
  String toString() => 'ApiException($statusCode from $uri: $body)';
}
