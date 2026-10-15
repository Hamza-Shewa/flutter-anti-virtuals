import '../domain/app_attest.dart';
import '../domain/ports.dart';

/// An [AppAttestKeyStore] in this process's memory. Good for tests and a
/// single server instance; enrolled keys are lost on restart, so the apps
/// then need to enroll again (`resetAppAttestKey`). Use a database in
/// production.
final class InMemoryAppAttestKeyStore implements AppAttestKeyStore {
  final Map<String, AppAttestKey> _keys = {};

  @override
  AppAttestKey? find(String keyId) => _keys[keyId];

  @override
  bool save(AppAttestKey key) {
    if (_keys.containsKey(key.keyId)) return false;
    _keys[key.keyId] = key;
    return true;
  }

  @override
  bool compareAndSetCounter(
    String keyId, {
    required int expected,
    required int next,
  }) {
    final key = _keys[keyId];
    if (key == null || key.counter != expected) return false;
    _keys[keyId] = key.withCounter(next);
    return true;
  }
}
