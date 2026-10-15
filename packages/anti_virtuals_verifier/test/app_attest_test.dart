import 'dart:convert';
import 'dart:typed_data';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:test/test.dart';

import 'support/apple_sample.dart';
import 'support/fake_app_attest.dart';
import 'support/fake_device.dart';

void main() {
  Matcher failsWith(RejectionReason reason) => throwsA(
    isA<AppAttestException>().having((e) => e.reason, 'reason', reason),
  );
  Matcher rejectedFor(RejectionReason reason) =>
      isA<Rejected>().having((r) => r.reason, 'reason', reason);

  group("Apple's sample attestation", () {
    final attestation = base64.decode(appleSampleAttestation);
    final challenge = utf8.encode(appleSampleChallenge);
    final validAt = DateTime.utc(2026, 4, 21, 18, 14);

    AppAttestVerifier verifier({
      String team = '1234567890',
      String bundle = 'com.example.myapp',
    }) => AppAttestVerifier(
      policy: IosPolicy(teamId: team, bundleIds: {bundle}),
      keys: InMemoryAppAttestKeyStore(),
      clock: () => validAt,
    );

    test('verifies against the embedded Apple root', () async {
      final result = await verifier().verifyAttestation(
        attestation: attestation,
        keyId: appleSampleKeyId,
        clientDataHash: challenge,
      );
      expect(result.isNewKey, isTrue);
      expect(result.keyId, appleSampleKeyId);
      expect(result.appId, appleSampleAppId);
      expect(result.environment, AppleEnvironment.production);
      expect(result.counter, 0);
      expect(result.validationCategory, 1);
      expect(result.bundleVersion, '1');
      expect(base64.encode(sha256(result.publicKey)), appleSampleKeyId);
      expect(result.receipt, isNotEmpty);
    });

    test('fails for another challenge, app or time', () async {
      expect(
        verifier().verifyAttestation(
          attestation: attestation,
          keyId: appleSampleKeyId,
          clientDataHash: sha256(challenge),
        ),
        failsWith(RejectionReason.challengeMismatch),
      );
      expect(
        verifier(team: '0987654321').verifyAttestation(
          attestation: attestation,
          keyId: appleSampleKeyId,
          clientDataHash: challenge,
        ),
        failsWith(RejectionReason.wrongApp),
      );
      expect(
        AppAttestVerifier(
          policy: const IosPolicy(
            teamId: '1234567890',
            bundleIds: {'com.example.myapp'},
          ),
          keys: InMemoryAppAttestKeyStore(),
        ).verifyAttestation(
          attestation: attestation,
          keyId: appleSampleKeyId,
          clientDataHash: challenge,
          now: DateTime.utc(2026, 10, 14),
        ),
        failsWith(RejectionReason.untrustedChain),
      );
    });

    test('its receipt verifies up to Apple Root CA - G3', () {
      final receipt = verifierReceipt(attestation);
      final read = AppAttestReceiptReader(
        clock: () => validAt,
      ).read(receipt, appId: appleSampleAppId);
      expect(read.type, AppAttestReceiptType.attest);
      expect(read.appId, appleSampleAppId);
      expect(read.createdAt, DateTime.utc(2026, 4, 21, 18, 13, 12, 153));
      expect(read.expiresAt, DateTime.utc(2026, 7, 20, 18, 13, 12, 153));
      expect(read.riskMetric, isNull);
      expect(utf8.decode(read.clientHash!), appleSampleChallenge);
      expect(base64.encode(sha256(read.attestedPublicKey!)), appleSampleKeyId);
      expect(read.fields[7], utf8.encode('production'));
    });

    test('its receipt fails when changed or under another root', () {
      final receipt = verifierReceipt(attestation);
      final reader = AppAttestReceiptReader(clock: () => validAt);
      final changed = Uint8List.fromList(receipt);
      final at = _indexOf(changed, utf8.encode('ATTEST'));
      changed[at] = 'B'.codeUnitAt(0);
      expect(
        () => reader.read(changed),
        throwsA(isA<InvalidReceiptException>()),
      );
      expect(
        () => AppAttestReceiptReader(
          trustedRoots: AppleRoots.appAttestKeys,
          clock: () => validAt,
        ).read(receipt),
        throwsA(isA<InvalidReceiptException>()),
      );
      expect(
        () => reader.read(receipt, appId: 'ABCDE12345.com.other'),
        throwsA(isA<InvalidReceiptException>()),
      );
      expect(
        () => reader.read(receipt, maxAge: const Duration(seconds: 5)),
        throwsA(isA<InvalidReceiptException>()),
      );
      expect(
        () => reader.read(receipt, publicKey: Uint8List(65)..[0] = 4),
        throwsA(isA<InvalidReceiptException>()),
      );
      expect(
        () => reader.read(Uint8List.fromList([0x30, 0x80, 0x06])),
        throwsA(isA<InvalidReceiptException>()),
      );
    });

    test('the embedded roots parse and sign themselves', () {
      for (final pem in [AppleRoots.appAttestationRoot, AppleRoots.rootCaG3]) {
        final root = X509Certificate.fromPem(pem);
        expect(root.isSignedBy(root.publicKey), isTrue);
        expect(root.publicKey, isA<EcPublicKey>());
      }
    });
  });

  group('SignedReportVerifier on iOS', () {
    final now = DateTime.utc(2026, 10, 14, 12);
    late FakeDevice device;
    late FakeAppAttest apple;
    late InMemoryNonceStore nonces;
    late InMemoryAppAttestKeyStore keys;

    setUp(() {
      device = FakeDevice();
      apple = FakeAppAttest();
      nonces = InMemoryNonceStore(clock: () => now);
      keys = InMemoryAppAttestKeyStore();
    });

    SignedReportVerifier verifier({
      IosPolicy ios = const IosPolicy(teamId: teamId, bundleIds: {bundleId}),
      List<PublicKey>? roots,
    }) => SignedReportVerifier(
      nonces: nonces,
      policy: VerificationPolicy(ios: ios),
      appAttestKeys: keys,
      appAttestRoots: roots ?? apple.roots,
      clock: () => now,
    );

    Future<VerificationResult> send(
      Map<String, Object?>? Function(String payload) attestation, {
      SignedReportVerifier? using,
    }) => (using ?? verifier()).verify(
      device.iosReport(
        nonce: nonces.issue(),
        issuedAt: now,
        attestation: attestation,
      ),
    );

    test(
      'enrolls a key, then accepts assertions with a rising counter',
      () async {
        final key = apple.newKey();
        final first = await send(
          (p) => key.attestationMap(p, deviceCheckToken: 'dc-token'),
        );
        expect(first, isA<Accepted>());
        final enrolled = (first as Accepted).appAttest!;
        expect(enrolled.isNewKey, isTrue);
        expect(enrolled.keyId, key.keyId);
        expect(enrolled.appId, appId);
        expect(enrolled.counter, 0);
        expect(utf8.decode(enrolled.receipt!), 'test receipt');
        expect(first.deviceCheckToken, 'dc-token');
        expect(keys.find(key.keyId)!.publicKey, key.key.point);

        for (final counter in [1, 2, 5]) {
          final result = await send(
            (p) => key.assertionMap(
              p,
              object: (h) => key.assertion(h, withCounter: counter),
            ),
          );
          expect(result, isA<Accepted>());
          final asserted = (result as Accepted).appAttest!;
          expect(asserted.isNewKey, isFalse);
          expect(asserted.counter, counter);
          expect(asserted.receipt, isNull);
          expect(keys.find(key.keyId)!.counter, counter);
        }
      },
    );

    test('rejects an assertion whose counter did not increase', () async {
      final key = apple.newKey();
      await send(key.attestationMap);
      expect(await send(key.assertionMap), isA<Accepted>());
      expect(
        await send(
          (p) => key.assertionMap(
            p,
            object: (h) => key.assertion(h, withCounter: 1),
          ),
        ),
        rejectedFor(RejectionReason.appAttestReplay),
      );
      expect(
        await send(
          (p) => key.assertionMap(
            p,
            object: (h) => key.assertion(h, withCounter: 0),
          ),
        ),
        rejectedFor(RejectionReason.appAttestReplay),
      );
    });

    test('rejects an assertion for a key it never enrolled', () async {
      expect(
        await send(apple.newKey().assertionMap),
        rejectedFor(RejectionReason.unknownAppAttestKey),
      );
    });

    test('rejects an assertion signed by another key', () async {
      final key = apple.newKey();
      await send(key.attestationMap);
      final other = apple.newKey().key;
      expect(
        await send(
          (p) => key.assertionMap(
            p,
            object: (h) => key.assertion(h, signWith: other),
          ),
        ),
        rejectedFor(RejectionReason.badSignature),
      );
    });

    test('rejects an assertion made for another payload', () async {
      final key = apple.newKey();
      await send(key.attestationMap);
      expect(
        await send(
          (p) => key.assertionMap(
            p,
            object: (_) => key.assertion(sha256(utf8.encode('other'))),
          ),
        ),
        rejectedFor(RejectionReason.badSignature),
      );
    });

    test('rejects an assertion for another app', () async {
      final key = apple.newKey();
      await send(key.attestationMap);
      expect(
        await send(
          (p) => key.assertionMap(
            p,
            object: (h) => key.assertion(h, forAppId: '$teamId.com.other'),
          ),
        ),
        rejectedFor(RejectionReason.wrongApp),
      );
      final twoApps = verifier(
        ios: const IosPolicy(
          teamId: teamId,
          bundleIds: {bundleId, 'com.example.other'},
        ),
      );
      expect(
        await send(
          (p) => key.assertionMap(
            p,
            object: (h) =>
                key.assertion(h, forAppId: '$teamId.com.example.other'),
          ),
          using: twoApps,
        ),
        rejectedFor(RejectionReason.wrongApp),
        reason: 'the key was enrolled for the other bundle id',
      );
    });

    test('rejects attestations that do not hold up', () async {
      Future<VerificationResult> attest(
        Uint8List Function(FakeAppAttestKey key, List<int> hash) object, {
        SignedReportVerifier? using,
      }) {
        final key = apple.newKey();
        return send(
          (p) => key.attestationMap(p, object: (h) => object(key, h)),
          using: using,
        );
      }

      expect(
        await attest((k, h) => k.attestation(h, nonceFor: sha256([1]))),
        rejectedFor(RejectionReason.challengeMismatch),
      );
      expect(
        await attest(
          (k, h) => k.attestation(h, forAppId: 'ZZZZZ99999.$bundleId'),
        ),
        rejectedFor(RejectionReason.wrongApp),
      );
      expect(
        await attest((k, h) => k.attestation(h, attestationCounter: 1)),
        rejectedFor(RejectionReason.notAttested),
      );
      expect(
        await attest(
          (k, h) =>
              k.attestation(h, aaguid: Uint8List.fromList(List.filled(16, 1))),
        ),
        rejectedFor(RejectionReason.notAttested),
      );
      expect(
        await attest((k, h) => k.attestation(h, credentialId: Uint8List(32))),
        rejectedFor(RejectionReason.keyMismatch),
      );
      expect(
        await attest((k, h) => k.attestation(h, chainToRoot: false)),
        rejectedFor(RejectionReason.untrustedChain),
      );
      expect(
        await attest(
          (k, h) => k.attestation(h, notAfter: DateTime.utc(2026, 6)),
        ),
        rejectedFor(RejectionReason.untrustedChain),
      );
      expect(
        await attest(
          (k, h) => k.attestation(h),
          using: verifier(roots: AppleRoots.appAttestKeys),
        ),
        rejectedFor(RejectionReason.untrustedChain),
      );
      expect(
        await attest((k, h) => Uint8List.fromList([0xa0])),
        rejectedFor(RejectionReason.notAttested),
      );
    });

    test('rejects a key id that is not the attested key', () async {
      final key = apple.newKey();
      final other = apple.newKey();
      expect(
        await send((p) => {...key.attestationMap(p), 'keyId': other.keyId}),
        rejectedFor(RejectionReason.keyMismatch),
      );
      expect(
        await send((p) => {...key.attestationMap(p), 'keyId': 'not base64!'}),
        rejectedFor(RejectionReason.keyMismatch),
      );
    });

    test('rejects a key that is attested twice', () async {
      final key = apple.newKey();
      expect(await send(key.attestationMap), isA<Accepted>());
      expect(
        await send(key.attestationMap),
        rejectedFor(RejectionReason.appAttestReplay),
      );
    });

    test('accepts development keys only when the policy allows them', () async {
      final key = apple.newKey();
      Map<String, Object?> development(String payload) => key.attestationMap(
        payload,
        object: (h) => key.attestation(h, aaguid: developmentAaguid),
      );
      expect(
        await send(development),
        rejectedFor(RejectionReason.wrongEnvironment),
      );
      final result = await send(
        development,
        using: verifier(
          ios: const IosPolicy(
            teamId: teamId,
            bundleIds: {bundleId},
            allowDevelopment: true,
          ),
        ),
      );
      expect(
        (result as Accepted).appAttest!.environment,
        AppleEnvironment.development,
      );
      // A stricter policy later refuses the enrolled development key.
      expect(
        await send(key.assertionMap),
        rejectedFor(RejectionReason.wrongEnvironment),
      );
    });

    test('checks the validation category when the policy lists them', () async {
      final strict = verifier(
        ios: const IosPolicy(
          teamId: teamId,
          bundleIds: {bundleId},
          allowedValidationCategories: {2, 4},
        ),
      );
      Map<String, Object?> Function(String) withCategory(
        FakeAppAttestKey key,
        int category,
      ) =>
          (p) => key.attestationMap(
            p,
            object: (h) => key.attestation(
              h,
              extensions: {
                'apple_bundle_version_01': '7',
                'apple_validation_category_01': Uint8List.fromList([
                  category,
                  0,
                  0,
                  0,
                ]),
              },
            ),
          );

      final appStore = apple.newKey();
      final accepted = await send(withCategory(appStore, 4), using: strict);
      expect((accepted as Accepted).appAttest!.validationCategory, 4);
      expect(accepted.appAttest!.bundleVersion, '7');
      expect(
        await send(withCategory(apple.newKey(), 3), using: strict),
        rejectedFor(RejectionReason.wrongApp),
      );
      expect(
        await send(
          (p) => appStore.assertionMap(
            p,
            object: (h) =>
                appStore.assertion(h, extensions: {'validationCategory': 3}),
          ),
          using: strict,
        ),
        rejectedFor(RejectionReason.wrongApp),
      );
      expect(
        await send(apple.newKey().attestationMap, using: strict),
        isA<Accepted>(),
        reason: 'objects without the extension pass',
      );
    });

    test('requires App Attest unless the policy says otherwise', () async {
      expect(await send((_) => null), rejectedFor(RejectionReason.notAttested));
      expect(
        await send((_) => {'type': 'appAttest', 'token': 'AA=='}),
        rejectedFor(RejectionReason.notAttested),
      );
      final optional = verifier(
        ios: const IosPolicy(
          teamId: teamId,
          bundleIds: {bundleId},
          requireAppAttest: false,
        ),
      );
      final result = await send((_) => null, using: optional);
      expect((result as Accepted).appAttest, isNull);
      expect(
        await send((p) => apple.newKey().assertionMap(p), using: optional),
        rejectedFor(RejectionReason.unknownAppAttestKey),
        reason: 'an object that is present must verify',
      );
    });

    test('needs a key store when the policy has an iOS part', () {
      expect(
        () => SignedReportVerifier(
          nonces: nonces,
          policy: const VerificationPolicy(
            ios: IosPolicy(teamId: teamId, bundleIds: {bundleId}),
          ),
        ),
        throwsArgumentError,
      );
    });
  });

  group('InMemoryAppAttestKeyStore', () {
    test('saves a key once and moves its counter by compare and set', () {
      final store = InMemoryAppAttestKeyStore();
      final key = AppAttestKey(
        keyId: 'k',
        publicKey: Uint8List(65),
        appId: appId,
        environment: AppleEnvironment.production,
      );
      expect(store.find('k'), isNull);
      expect(store.save(key), isTrue);
      expect(store.save(key), isFalse);
      expect(store.compareAndSetCounter('k', expected: 0, next: 3), isTrue);
      expect(store.compareAndSetCounter('k', expected: 0, next: 4), isFalse);
      expect(store.find('k')!.counter, 3);
      expect(store.compareAndSetCounter('x', expected: 0, next: 1), isFalse);
    });
  });
}

/// The receipt of an attestation object.
Uint8List verifierReceipt(Uint8List attestation) {
  final at = _indexOf(attestation, utf8.encode('receipt'));
  // "receipt" is followed by a byte string head 0x59 and a 2-byte length.
  final length = (attestation[at + 8] << 8) | attestation[at + 9];
  return Uint8List.sublistView(attestation, at + 10, at + 10 + length);
}

int _indexOf(List<int> data, List<int> part) {
  for (var i = 0; i + part.length <= data.length; i++) {
    var match = true;
    for (var j = 0; j < part.length && match; j++) {
      match = data[i + j] == part[j];
    }
    if (match) return i;
  }
  throw StateError('Not found');
}
