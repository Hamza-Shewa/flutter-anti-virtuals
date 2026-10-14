import 'dart:convert';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:test/test.dart';

import 'support/fake_device.dart';

void main() {
  final now = DateTime.utc(2026, 10, 14, 12);

  String digest64() => base64Url
      .encode([
        for (var i = 0; i < 32; i++)
          int.parse(signingDigest.substring(i * 2, i * 2 + 2), radix: 16),
      ])
      .replaceAll('=', '');

  /// A verdict like Google's documentation shows, bound to [payload], with
  /// every optional response turned on.
  Map<String, Object?> verdict(
    String payload, {
    String recognition = 'PLAY_RECOGNIZED',
    List<String> device = const [
      'MEETS_BASIC_INTEGRITY',
      'MEETS_DEVICE_INTEGRITY',
    ],
    String licensing = 'LICENSED',
    Object? appsDetected = const ['KNOWN_INSTALLED'],
    String? playProtect = 'NO_ISSUES',
    String? activity = 'LEVEL_1',
  }) => {
    'requestDetails': {
      'requestPackageName': packageName,
      'requestHash': base64Url
          .encode(sha256(utf8.encode(payload)))
          .replaceAll('=', ''),
      'timestampMillis': '${now.millisecondsSinceEpoch - 1000}',
    },
    'appIntegrity': {
      'appRecognitionVerdict': recognition,
      'packageName': packageName,
      'certificateSha256Digest': [digest64()],
      'versionCode': '42',
    },
    'deviceIntegrity': {
      'deviceRecognitionVerdict': device,
      'deviceAttributes': {'sdkVersion': 34},
      'recentDeviceActivity': {'deviceActivityLevel': ?activity},
      'deviceRecall': {
        'values': {'bitFirst': true, 'bitSecond': false, 'bitThird': true},
        'writeDates': {'yyyymmFirst': 202401, 'yyyymmThird': 202310},
      },
    },
    'accountDetails': {'appLicensingVerdict': licensing},
    'environmentDetails': {
      'appAccessRiskVerdict': {'appsDetected': ?appsDetected},
      'playProtectVerdict': ?playProtect,
    },
    'testingDetails': {'isTestingResponse': false},
  };

  group('PlayIntegrityVerdict', () {
    test('reads every documented field', () {
      final parsed = PlayIntegrityVerdict.fromJson(verdict('x'));
      expect(parsed.requestDetails.requestPackageName, packageName);
      expect(parsed.requestDetails.requestHash, isNotNull);
      expect(parsed.requestDetails.nonce, isNull);
      expect(
        parsed.requestDetails.timestamp,
        now.subtract(const Duration(seconds: 1)),
      );
      expect(
        parsed.appIntegrity.appRecognitionVerdict,
        AppRecognitionVerdict.playRecognized,
      );
      expect(parsed.appIntegrity.certificateSha256Hex, {signingDigest});
      expect(parsed.appIntegrity.versionCode, 42);
      final device = parsed.deviceIntegrity;
      expect(device.deviceRecognitionVerdict, {
        DeviceRecognitionLabel.meetsBasicIntegrity,
        DeviceRecognitionLabel.meetsDeviceIntegrity,
      });
      expect(device.sdkVersion, 34);
      expect(device.deviceActivityLevel, DeviceActivityLevel.level1);
      final recall = device.deviceRecall!;
      expect(recall.values.bitFirst, isTrue);
      expect(recall.values.bitSecond, isFalse);
      expect(recall.values.bitThird, isTrue);
      expect(recall.writeDates.yyyymmFirst, 202401);
      expect(recall.writeDates.yyyymmSecond, isNull);
      expect(recall.writeDates.yyyymmThird, 202310);
      expect(
        parsed.accountDetails.appLicensingVerdict,
        AppLicensingVerdict.licensed,
      );
      expect(parsed.environmentDetails.appsDetected, {
        AppAccessRisk.knownInstalled,
      });
      expect(
        parsed.environmentDetails.playProtectVerdict,
        PlayProtectVerdict.noIssues,
      );
      expect(parsed.isTestingResponse, isFalse);
    });

    test('reads missing and malformed parts as absent', () {
      final parsed = PlayIntegrityVerdict.fromJson({
        'requestDetails': 'nope',
        'appIntegrity': {
          'appRecognitionVerdict': 'SOMETHING_NEW',
          'certificateSha256Digest': [1, '!!!', 'AQID'],
        },
        'deviceIntegrity': {
          'deviceRecognitionVerdict': [
            'MEETS_DEVICE_INTEGRITY',
            'NEW_LABEL',
            3,
          ],
          'deviceAttributes': {},
        },
        'environmentDetails': {'appAccessRiskVerdict': {}},
        'testingDetails': {'isTestingResponse': true},
      });
      expect(parsed.requestDetails.requestPackageName, isNull);
      expect(parsed.requestDetails.timestamp, isNull);
      expect(parsed.appIntegrity.appRecognitionVerdict, isNull);
      expect(parsed.appIntegrity.certificateSha256Hex, {'010203'});
      expect(parsed.deviceIntegrity.deviceRecognitionVerdict, {
        DeviceRecognitionLabel.meetsDeviceIntegrity,
      });
      expect(parsed.deviceIntegrity.sdkVersion, isNull);
      expect(parsed.deviceIntegrity.deviceRecall, isNull);
      expect(parsed.environmentDetails.appsDetected, isNull);
      expect(parsed.environmentDetails.playProtectVerdict, isNull);
      expect(parsed.accountDetails.appLicensingVerdict, isNull);
      expect(parsed.isTestingResponse, isTrue);
    });

    test('enum values are the strings Google sends', () {
      expect(AppAccessRisk.unknownCapturing.value, 'UNKNOWN_CAPTURING');
      expect(PlayProtectVerdict.possibleRisk.value, 'POSSIBLE_RISK');
      expect(DeviceActivityLevel.level4.value, 'LEVEL_4');
      expect(
        DeviceRecognitionLabel.meetsStrongIntegrity.value,
        'MEETS_STRONG_INTEGRITY',
      );
      expect(
        AppLicensingVerdict.parse('UNLICENSED'),
        AppLicensingVerdict.unlicensed,
      );
      expect(AppRecognitionVerdict.parse('nope'), isNull);
    });

    test('device activity levels compare in order', () {
      expect(
        DeviceActivityLevel.level2.isAtMost(DeviceActivityLevel.level2),
        isTrue,
      );
      expect(
        DeviceActivityLevel.level1.isAtMost(DeviceActivityLevel.level3),
        isTrue,
      );
      expect(
        DeviceActivityLevel.level4.isAtMost(DeviceActivityLevel.level3),
        isFalse,
      );
      expect(
        DeviceActivityLevel.unevaluated.isAtMost(DeviceActivityLevel.level4),
        isFalse,
      );
    });

    test('remediation names and codes match the plugin dialogs', () {
      // flutter_anti_virtuals: PlayIntegrityDialog in lib/src/attestation.dart.
      expect(
        {for (final r in PlayIntegrityRemediation.values) r.name: r.typeCode},
        {
          'getLicensed': 1,
          'closeUnknownAccessRisk': 2,
          'closeAllAccessRisk': 3,
          'getIntegrity': 4,
          'getStrongIntegrity': 5,
        },
      );
    });

    test('device recall values serialize without null bits', () {
      expect(
        const DeviceRecallValues(bitFirst: true, bitThird: false).toJson(),
        {'bitFirst': true, 'bitThird': false},
      );
      expect(const DeviceRecallValues().isEmpty, isTrue);
    });
  });

  group('PlayIntegrityCheck', () {
    late FakeDevice device;
    late InMemoryNonceStore nonces;

    setUp(() {
      device = FakeDevice();
      nonces = InMemoryNonceStore(clock: () => now);
    });

    Future<VerificationResult> verify(
      Map<String, Object?> Function(String payload) build, {
      PlayIntegrityPolicy policy = const PlayIntegrityPolicy(),
    }) {
      final report = device.androidReport(nonce: nonces.issue(), issuedAt: now);
      return SignedReportVerifier(
        nonces: nonces,
        policy: VerificationPolicy(
          android: AndroidPolicy(
            packageNames: const {packageName},
            signingCertificateDigests: const {signingDigest},
            playIntegrity: policy,
          ),
        ),
        trustedRoots: device.roots,
        clock: () => now,
      ).verify(
        report,
        playIntegrityVerdict: build(report['payload']! as String),
      );
    }

    Matcher rejected({PlayIntegrityRemediation? remediation}) => isA<Rejected>()
        .having((r) => r.reason, 'reason', RejectionReason.playIntegrity)
        .having((r) => r.remediation, 'remediation', remediation)
        .having((r) => r.playIntegrityVerdict, 'verdict', isNotNull);

    test('accepts a genuine verdict and returns it', () async {
      final result = await verify(verdict);
      expect(result, isA<Accepted>());
      final accepted = (result as Accepted).playIntegrityVerdict!;
      expect(accepted.deviceIntegrity.deviceRecall!.values.bitFirst, isTrue);
      expect(result.keyAttestation, isNotNull);
    });

    test(
      'no dialog for a token that is not bound, old or for another app',
      () async {
        expect(await verify((_) => verdict('other')), rejected());
        expect(
          await verify(
            (p) => verdict(p)
              ..['requestDetails'] = {
                ...verdict(p)['requestDetails']! as Map<String, Object?>,
                'requestPackageName': 'com.other',
              },
          ),
          rejected(),
        );
        expect(
          await verify(
            (p) => verdict(p)
              ..['requestDetails'] = {
                ...verdict(p)['requestDetails']! as Map<String, Object?>,
                'timestampMillis': '${now.millisecondsSinceEpoch - 600000}',
              },
          ),
          rejected(),
        );
      },
    );

    test('app recognition: GET_LICENSED or GET_INTEGRITY', () async {
      expect(
        await verify((p) => verdict(p, recognition: 'UNRECOGNIZED_VERSION')),
        rejected(remediation: PlayIntegrityRemediation.getLicensed),
      );
      expect(
        await verify((p) => verdict(p, recognition: 'UNEVALUATED')),
        rejected(remediation: PlayIntegrityRemediation.getIntegrity),
      );
    });

    test('device integrity: GET_INTEGRITY or GET_STRONG_INTEGRITY', () async {
      expect(
        await verify(
          (p) => verdict(p, device: const ['MEETS_BASIC_INTEGRITY']),
        ),
        rejected(remediation: PlayIntegrityRemediation.getIntegrity),
      );
      expect(
        await verify(
          verdict,
          policy: const PlayIntegrityPolicy(
            requiredDeviceVerdict: DeviceRecognitionLabel.meetsStrongIntegrity,
          ),
        ),
        rejected(remediation: PlayIntegrityRemediation.getStrongIntegrity),
      );
      expect(
        await verify(
          (p) => verdict(p, device: const []),
          policy: const PlayIntegrityPolicy(requiredDeviceVerdict: null),
        ),
        isA<Accepted>(),
      );
    });

    test('licensing: GET_LICENSED or GET_INTEGRITY', () async {
      const policy = PlayIntegrityPolicy(requireLicensed: true);
      expect(
        await verify(
          (p) => verdict(p, licensing: 'UNLICENSED'),
          policy: policy,
        ),
        rejected(remediation: PlayIntegrityRemediation.getLicensed),
      );
      expect(
        await verify(
          (p) => verdict(p, licensing: 'UNEVALUATED'),
          policy: policy,
        ),
        rejected(remediation: PlayIntegrityRemediation.getIntegrity),
      );
      expect(
        await verify((p) => verdict(p, licensing: 'UNLICENSED')),
        isA<Accepted>(),
        reason: 'licensing is not required by default',
      );
    });

    test('app access risk: the close dialogs', () async {
      const policy = PlayIntegrityPolicy(
        rejectedAppAccessRisks: AppAccessRisk.capturingOrControlling,
      );
      expect(
        await verify(
          (p) => verdict(
            p,
            appsDetected: const ['KNOWN_INSTALLED', 'UNKNOWN_CAPTURING'],
          ),
          policy: policy,
        ),
        rejected(remediation: PlayIntegrityRemediation.closeUnknownAccessRisk),
      );
      expect(
        await verify(
          (p) => verdict(
            p,
            appsDetected: const ['KNOWN_CONTROLLING', 'UNKNOWN_CAPTURING'],
          ),
          policy: policy,
        ),
        rejected(remediation: PlayIntegrityRemediation.closeAllAccessRisk),
      );
      expect(
        await verify(
          (p) => verdict(p, appsDetected: const ['UNKNOWN_OVERLAYS']),
          policy: const PlayIntegrityPolicy(
            rejectedAppAccessRisks: {AppAccessRisk.unknownOverlays},
          ),
        ),
        rejected(),
      );
      expect(
        await verify(
          (p) => verdict(p, appsDetected: const ['KNOWN_CAPTURING']),
          policy: const PlayIntegrityPolicy(
            rejectedAppAccessRisks: AppAccessRisk.unknownCapturingOrControlling,
          ),
        ),
        isA<Accepted>(),
      );
    });

    test('app access risk that was not evaluated', () async {
      Map<String, Object?> unevaluated(String p) =>
          verdict(p, appsDetected: null);
      expect(
        await verify(
          unevaluated,
          policy: const PlayIntegrityPolicy(
            rejectedAppAccessRisks: AppAccessRisk.capturingOrControlling,
          ),
        ),
        isA<Accepted>(),
      );
      expect(
        await verify(
          unevaluated,
          policy: const PlayIntegrityPolicy(requireAppAccessRiskVerdict: true),
        ),
        rejected(),
      );
    });

    test('Play Protect: GET_STRONG_INTEGRITY', () async {
      const policy = PlayIntegrityPolicy(
        acceptedPlayProtectVerdicts: {
          PlayProtectVerdict.noIssues,
          PlayProtectVerdict.noData,
        },
      );
      expect(await verify(verdict, policy: policy), isA<Accepted>());
      for (final value in ['POSSIBLE_RISK', 'MEDIUM_RISK', 'HIGH_RISK', null]) {
        expect(
          await verify((p) => verdict(p, playProtect: value), policy: policy),
          rejected(remediation: PlayIntegrityRemediation.getStrongIntegrity),
          reason: '$value',
        );
      }
    });

    test('recent device activity: a cap without a dialog', () async {
      const policy = PlayIntegrityPolicy(
        maxDeviceActivityLevel: DeviceActivityLevel.level2,
      );
      expect(
        await verify((p) => verdict(p, activity: 'LEVEL_2'), policy: policy),
        isA<Accepted>(),
      );
      for (final level in ['LEVEL_3', 'LEVEL_4', 'UNEVALUATED', null]) {
        expect(
          await verify((p) => verdict(p, activity: level), policy: policy),
          rejected(),
          reason: '$level',
        );
      }
    });
  });
}
