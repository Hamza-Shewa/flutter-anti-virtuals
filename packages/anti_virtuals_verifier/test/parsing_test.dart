import 'dart:typed_data';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:test/test.dart';

void main() {
  group("Google's roots", () {
    test('parse and verify their own signatures (RSA 4096 and P-384)', () {
      final rsa = X509Certificate.fromPem(GoogleAttestationRoots.rsaRoot);
      final ec = X509Certificate.fromPem(GoogleAttestationRoots.ecRoot);
      expect(rsa.publicKey, isA<RsaPublicKey>());
      expect(ec.publicKey, isA<EcPublicKey>());
      expect(rsa.isSignedBy(rsa.publicKey), isTrue);
      expect(ec.isSignedBy(ec.publicKey), isTrue);
      expect(rsa.isSignedBy(ec.publicKey), isFalse);
      expect(GoogleAttestationRoots.keys, hasLength(2));
    });
  });

  group('malformed input', () {
    test('is a FormatException, never another error', () {
      for (final bytes in [
        <int>[],
        [0x30],
        [0x30, 0x05, 0x02, 0x01],
        [0x30, 0x80, 0x00, 0x00],
        [0x30, 0x03, 0x02, 0x01, 0x01],
        List<int>.generate(64, (i) => i * 7 % 256),
      ]) {
        expect(
          () => X509Certificate.fromDer(Uint8List.fromList(bytes)),
          throwsFormatException,
          reason: '$bytes',
        );
        expect(
          () => PublicKey.fromSpki(Uint8List.fromList(bytes)),
          throwsFormatException,
          reason: '$bytes',
        );
      }
    });

    test('a payload that is not a version 1 report', () {
      for (final payload in ['', 'null', '[]', '{"v":1}', '{"v":2}']) {
        expect(() => DeviceReport.parse(payload), throwsFormatException);
      }
    });
  });

  group('InMemoryNonceStore', () {
    test('accepts a nonce once and not after it expired', () {
      var now = DateTime.utc(2026);
      final store = InMemoryNonceStore(
        lifetime: const Duration(minutes: 1),
        clock: () => now,
      );
      final first = store.issue();
      expect(first.length, greaterThanOrEqualTo(43));
      expect(store.consume(first), isTrue);
      expect(store.consume(first), isFalse);
      final second = store.issue();
      now = now.add(const Duration(minutes: 2));
      expect(store.consume(second), isFalse);
      expect(store.consume('never-issued'), isFalse);
    });
  });
}
