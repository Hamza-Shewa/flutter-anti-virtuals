import 'dart:convert';
import 'dart:math';

import '../domain/ports.dart';

/// A [NonceStore] in this process's memory. Good for tests and a single
/// server instance; several instances need a shared store such as Redis.
final class InMemoryNonceStore implements NonceStore {
  InMemoryNonceStore({
    this.lifetime = const Duration(minutes: 5),
    DateTime Function()? clock,
  }) : _clock = clock ?? DateTime.now;

  /// How long an issued nonce stays usable.
  final Duration lifetime;
  final DateTime Function() _clock;
  final Map<String, DateTime> _expiries = {};
  final Random _random = Random.secure();

  /// Issues a new random nonce (32 bytes, URL-safe base64).
  String issue() {
    _expiries.removeWhere((_, expiry) => !expiry.isAfter(_clock()));
    final bytes = List<int>.generate(32, (_) => _random.nextInt(256));
    final nonce = base64Url.encode(bytes).replaceAll('=', '');
    _expiries[nonce] = _clock().add(lifetime);
    return nonce;
  }

  @override
  bool consume(String nonce) {
    final expiry = _expiries.remove(nonce);
    return expiry != null && expiry.isAfter(_clock());
  }
}
