import 'dart:convert';
import 'dart:typed_data';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:test/test.dart';

import 'support/fake_device.dart';

void main() {
  final now = DateTime.utc(2026, 10, 14, 12);
  late FakeDevice device;
  late InMemoryNonceStore nonces;

  setUp(() {
    device = FakeDevice();
    nonces = InMemoryNonceStore(clock: () => now);
  });

  SignedReportVerifier verifier({
    AndroidPolicy android = const AndroidPolicy(
      packageNames: {packageName},
      signingCertificateDigests: {signingDigest},
    ),
    bool acceptIos = false,
    RevocationList? revocations,
    List<PublicKey>? roots,
  }) => SignedReportVerifier(
    nonces: nonces,
    policy: VerificationPolicy(android: android, acceptIos: acceptIos),
    trustedRoots: roots ?? device.roots,
    revocations: revocations,
    clock: () => now,
  );

  Future<VerificationResult> verifyAndroid({
    SignedReportVerifier? using,
    Map<String, Object?> signals = const {
      'vpn': {'detected': false, 'supported': true},
    },
    Uint8List? description,
    DateTime? issuedAt,
    bool attestOtherKey = false,
    Map<String, Object?>? playIntegrityVerdict,
  }) {
    final nonce = nonces.issue();
    return (using ?? verifier()).verify(
      device.androidReport(
        nonce: nonce,
        issuedAt: issuedAt ?? now.subtract(const Duration(seconds: 5)),
        signals: signals,
        description: description,
        attestOtherKey: attestOtherKey,
      ),
      playIntegrityVerdict: playIntegrityVerdict,
    );
  }

  Matcher rejectedFor(RejectionReason reason) =>
      isA<Rejected>().having((r) => r.reason, 'reason', reason);

  group('accepts', () {
    test('a genuine Android report and returns what was attested', () async {
      final result = await verifyAndroid();
      expect(result, isA<Accepted>());
      final attestation = (result as Accepted).keyAttestation!;
      expect(attestation.securityLevel, SecurityLevel.trustedEnvironment);
      expect(attestation.packageNames, {packageName});
      expect(attestation.verifiedBootState, VerifiedBootState.verified);
      expect(attestation.deviceLocked, isTrue);
      expect(attestation.osPatchLevel, 202409);
      expect(result.report.platform, DevicePlatform.android);
    });

    test('an iOS report when the policy accepts iOS', () async {
      final result = await verifier(
        acceptIos: true,
      ).verify(device.iosReport(nonce: nonces.issue(), issuedAt: now));
      expect(result, isA<Accepted>());
      expect((result as Accepted).keyAttestation, isNull);
    });

    test('an installed-only detection unless told otherwise', () async {
      final result = await verifyAndroid(
        signals: const {
          'mockLocation': {
            'detected': true,
            'supported': true,
            'installedOnly': true,
          },
        },
      );
      expect(result, isA<Accepted>());
    });

    test('a report without a signal it blocks on (not checked)', () async {
      expect(await verifyAndroid(signals: const {}), isA<Accepted>());
    });

    test('signing certificate digests written with colons', () async {
      final colons = [
        for (var i = 0; i < signingDigest.length; i += 2)
          signingDigest.substring(i, i + 2).toUpperCase(),
      ].join(':');
      final result = await verifyAndroid(
        using: verifier(
          android: AndroidPolicy(
            packageNames: const {packageName},
            signingCertificateDigests: {colons},
          ),
        ),
      );
      expect(result, isA<Accepted>());
    });
  });

  group('rejects', () {
    test('something that is not a signed report', () async {
      expect(
        await verifier().verify({'payload': 'x'}),
        rejectedFor(RejectionReason.malformed),
      );
      expect(
        await verifier().verify({
          'payload': '{"v":2}',
          'signature': '',
          'publicKey': '',
        }),
        rejectedFor(RejectionReason.malformed),
      );
    });

    test('a replayed nonce', () async {
      final report = device.androidReport(nonce: nonces.issue(), issuedAt: now);
      expect(await verifier().verify(report), isA<Accepted>());
      expect(
        await verifier().verify(report),
        rejectedFor(RejectionReason.unknownNonce),
      );
    });

    test('a nonce this server never issued', () async {
      expect(
        await verifier().verify(
          device.androidReport(nonce: 'made-up-on-the-client', issuedAt: now),
        ),
        rejectedFor(RejectionReason.unknownNonce),
      );
    });

    test('an old report and one from the future', () async {
      expect(
        await verifyAndroid(issuedAt: now.subtract(const Duration(minutes: 5))),
        rejectedFor(RejectionReason.stale),
      );
      expect(
        await verifyAndroid(issuedAt: now.add(const Duration(minutes: 5))),
        rejectedFor(RejectionReason.stale),
      );
    });

    test('a payload changed after signing', () async {
      final report = device.androidReport(nonce: nonces.issue(), issuedAt: now);
      final payload = report['payload']! as String;
      report['payload'] = payload.replaceFirst(
        '"detected":false',
        '"detected":true',
      );
      expect(
        await verifier().verify(report),
        rejectedFor(RejectionReason.badSignature),
      );
    });

    test('iOS reports by default', () async {
      expect(
        await verifier().verify(
          device.iosReport(nonce: nonces.issue(), issuedAt: now),
        ),
        rejectedFor(RejectionReason.platformNotAccepted),
      );
    });

    test('Android reports when the policy has no Android part', () async {
      final noAndroid = SignedReportVerifier(
        nonces: nonces,
        policy: const VerificationPolicy(acceptIos: true),
        clock: () => now,
      );
      expect(
        await verifyAndroid(using: noAndroid),
        rejectedFor(RejectionReason.platformNotAccepted),
      );
    });

    test('a report without an attestation chain', () async {
      final report = device.androidReport(
        nonce: nonces.issue(),
        issuedAt: now,
        withChain: false,
      );
      expect(
        await verifier().verify(report),
        rejectedFor(RejectionReason.notAttested),
      );
    });

    test('a chain that does not lead to a trusted root', () async {
      expect(
        await verifyAndroid(
          using: verifier(roots: GoogleAttestationRoots.keys),
        ),
        rejectedFor(RejectionReason.untrustedChain),
      );
    });

    test('a revoked certificate, listed in hex or in decimal', () async {
      for (final serial in ['2c8cdddfd5e03bfc', '3210184587844008956']) {
        final revocations = GoogleStatusList({
          'entries': {
            serial: {'status': 'REVOKED', 'reason': 'KEY_COMPROMISE'},
          },
        });
        expect(
          await verifyAndroid(using: verifier(revocations: revocations)),
          rejectedFor(RejectionReason.revoked),
        );
      }
    });

    test('an attested key that did not sign the payload', () async {
      expect(
        await verifyAndroid(attestOtherKey: true),
        rejectedFor(RejectionReason.keyMismatch),
      );
    });

    test('a key created for another nonce', () async {
      expect(
        await verifyAndroid(
          description: keyDescription(challenge: sha256(utf8.encode('old'))),
        ),
        rejectedFor(RejectionReason.challengeMismatch),
      );
    });

    test('a software key', () async {
      final nonce = nonces.issue();
      final report = device.androidReport(
        nonce: nonce,
        issuedAt: now,
        description: keyDescription(
          challenge: sha256(utf8.encode(nonce)),
          securityLevel: 0,
        ),
      );
      expect(
        await verifier().verify(report),
        rejectedFor(RejectionReason.weakKeyStorage),
      );
    });

    Future<VerificationResult> withDescription(
      Uint8List Function(List<int> challenge) build, {
      SignedReportVerifier? using,
    }) {
      final nonce = nonces.issue();
      return (using ?? verifier()).verify(
        device.androidReport(
          nonce: nonce,
          issuedAt: now,
          description: build(sha256(utf8.encode(nonce))),
        ),
      );
    }

    test('another app, or yours re-signed', () async {
      expect(
        await withDescription(
          (c) => keyDescription(challenge: c, package: 'com.evil.app'),
        ),
        rejectedFor(RejectionReason.wrongApp),
      );
      expect(
        await withDescription(
          (c) => keyDescription(challenge: c, digest: '00' * 32),
        ),
        rejectedFor(RejectionReason.wrongApp),
      );
    });

    test('an unverified boot, an unlocked bootloader, an old patch', () async {
      expect(
        await withDescription(
          (c) => keyDescription(challenge: c, bootState: 2),
        ),
        rejectedFor(RejectionReason.unsafeDevice),
      );
      expect(
        await withDescription(
          (c) => keyDescription(challenge: c, locked: false),
        ),
        rejectedFor(RejectionReason.unsafeDevice),
      );
      expect(
        await withDescription(
          (c) => keyDescription(challenge: c, patchLevel: 202201),
          using: verifier(
            android: const AndroidPolicy(
              packageNames: {packageName},
              signingCertificateDigests: {signingDigest},
              minimumOsPatchLevel: 202401,
            ),
          ),
        ),
        rejectedFor(RejectionReason.unsafeDevice),
      );
    });

    test('a detected blocking signal and a failed blocking check', () async {
      expect(
        await verifyAndroid(
          signals: const {
            'rooted': {'detected': true, 'supported': true},
          },
        ),
        rejectedFor(RejectionReason.blockedSignal),
      );
      expect(
        await verifyAndroid(
          signals: const {
            'hooked': {'detected': false, 'supported': true, 'failed': true},
          },
        ),
        rejectedFor(RejectionReason.blockedSignal),
      );
    });
  });

  group('Play Integrity', () {
    SignedReportVerifier withPlayIntegrity() => verifier(
      android: const AndroidPolicy(
        packageNames: {packageName},
        signingCertificateDigests: {signingDigest},
        playIntegrity: PlayIntegrityPolicy(),
      ),
    );

    Future<VerificationResult> verifyWith(
      Map<String, Object?> Function(String payload) verdict,
    ) {
      final report = device.androidReport(nonce: nonces.issue(), issuedAt: now);
      return withPlayIntegrity().verify(
        report,
        playIntegrityVerdict: verdict(report['payload']! as String),
      );
    }

    Map<String, Object?> genuine(
      String payload, {
      String bindingField = 'requestHash',
      List<String> device = const ['MEETS_DEVICE_INTEGRITY'],
    }) => {
      'requestDetails': {
        'requestPackageName': packageName,
        bindingField: base64Url
            .encode(sha256(utf8.encode(payload)))
            .replaceAll('=', ''),
        'timestampMillis': '${now.millisecondsSinceEpoch - 1000}',
      },
      'appIntegrity': {
        'appRecognitionVerdict': 'PLAY_RECOGNIZED',
        'packageName': packageName,
        'certificateSha256Digest': [
          base64Url
              .encode(
                List.generate(
                  32,
                  (i) => int.parse(
                    signingDigest.substring(i * 2, i * 2 + 2),
                    radix: 16,
                  ),
                ),
              )
              .replaceAll('=', ''),
        ],
      },
      'deviceIntegrity': {'deviceRecognitionVerdict': device},
      'accountDetails': {'appLicensingVerdict': 'LICENSED'},
    };

    test(
      'accepts a standard and a classic verdict bound to the payload',
      () async {
        expect(await verifyWith(genuine), isA<Accepted>());
        expect(
          await verifyWith((p) => genuine(p, bindingField: 'nonce')),
          isA<Accepted>(),
        );
      },
    );

    test('rejects when no verdict was passed', () async {
      expect(
        await withPlayIntegrity().verify(
          device.androidReport(nonce: nonces.issue(), issuedAt: now),
        ),
        rejectedFor(RejectionReason.playIntegrity),
      );
    });

    test('rejects a verdict for another payload', () async {
      expect(
        await verifyWith((_) => genuine('another payload')),
        rejectedFor(RejectionReason.playIntegrity),
      );
    });

    test('rejects a device without device integrity', () async {
      expect(
        await verifyWith((p) => genuine(p, device: const [])),
        rejectedFor(RejectionReason.playIntegrity),
      );
    });
  });
}
