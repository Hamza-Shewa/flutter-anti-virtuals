import 'dart:async';

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
