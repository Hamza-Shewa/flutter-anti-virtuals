import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:anti_virtuals_verifier/io.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

import 'app_attest_test.dart' show verifierReceipt;
import 'support/apple_sample.dart';
import 'support/der_writer.dart';
import 'support/fake_device.dart';
import 'support/fake_receipt.dart';

const _ecPublicKey = '1.2.840.10045.2.1';
const _p256 = '1.2.840.10045.3.1.7';
const _ecdsaSha256 = '1.2.840.10045.4.3.2';

/// Answers every request with [respond] and remembers the requests.
final class FakeTransport implements HttpTransport {
  FakeTransport(this.respond);

  final TransportResponse Function(TransportRequest request) respond;
  final requests = <TransportRequest>[];

  TransportRequest get last => requests.last;

  @override
  Future<TransportResponse> send(TransportRequest request) async {
    requests.add(request);
    return respond(request);
  }
}

TransportResponse _ok([String body = '']) =>
    TransportResponse(statusCode: 200, body: utf8.encode(body));

Uint8List _fixed32(BigInt value) {
  final out = Uint8List(32);
  var v = value;
  for (var i = 31; i >= 0; i--) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return out;
}

String _pem(String label, List<int> der) {
  final body = base64.encode(der);
  final lines = [
    for (var i = 0; i < body.length; i += 64)
      body.substring(i, i + 64 > body.length ? body.length : i + 64),
  ];
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
}

/// The `.p8` file Apple hands out: PKCS #8 with a SEC1 key inside.
String p8(TestKey key) => _pem(
  'PRIVATE KEY',
  DerWriter.sequence([
    DerWriter.integer(0),
    DerWriter.sequence([DerWriter.oid(_ecPublicKey), DerWriter.oid(_p256)]),
    DerWriter.octets(
      DerWriter.sequence([
        DerWriter.integer(1),
        DerWriter.octets(_fixed32(key.private.d!)),
        DerWriter.explicit(1, DerWriter.bitString(key.point)),
      ]),
    ),
  ]),
);

String sec1(TestKey key) => _pem(
  'EC PRIVATE KEY',
  DerWriter.sequence([
    DerWriter.integer(1),
    DerWriter.octets(_fixed32(key.private.d!)),
    DerWriter.explicit(0, DerWriter.oid(_p256)),
    DerWriter.explicit(1, DerWriter.bitString(key.point)),
  ]),
);

Map<String, Object?> _jwtPart(String part) =>
    jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(part))))
        as Map<String, Object?>;

/// Checks the raw r||s ES256 signature of [token] with [key].
bool _jwtVerifies(String token, EcPublicKey key) {
  final parts = token.split('.');
  final raw = base64Url.decode(base64Url.normalize(parts[2]));
  if (raw.length != 64) return false;
  BigInt number(List<int> bytes) =>
      bytes.fold(BigInt.zero, (v, b) => (v << 8) | BigInt.from(b));
  final der = DerWriter.sequence([
    DerWriter.integer(number(raw.sublist(0, 32))),
    DerWriter.integer(number(raw.sublist(32))),
  ]);
  return key.verify(
    _ecdsaSha256,
    Uint8List.fromList(utf8.encode('${parts[0]}.${parts[1]}')),
    der,
  );
}

void main() {
  final random = pc.FortunaRandom()
    ..seed(pc.KeyParameter(Uint8List.fromList(List.filled(32, 9))));
  final appleKey = TestKey.generate(random);
  final now = DateTime.utc(2026, 10, 14, 12);

  AppleJwtSigner signer({DateTime Function()? clock}) => AppleJwtSigner(
    teamId: 'ABCDE12345',
    keyId: 'KEY1234567',
    privateKeyPem: p8(appleKey),
    clock: clock ?? () => now,
  );

  group('AppleJwtSigner', () {
    test('makes an ES256 token that verifies with the public key', () {
      final token = signer().sign();
      final parts = token.split('.');
      expect(parts, hasLength(3));
      expect(_jwtPart(parts[0]), {'alg': 'ES256', 'kid': 'KEY1234567'});
      expect(_jwtPart(parts[1]), {
        'iss': 'ABCDE12345',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
      });
      expect(token, isNot(contains('=')));
      expect(_jwtVerifies(token, EcPublicKey(_p256, appleKey.point)), isTrue);
      expect(signer().publicKey, EcPublicKey(_p256, appleKey.point));
      final other = TestKey.generate(random);
      expect(_jwtVerifies(token, EcPublicKey(_p256, other.point)), isFalse);
    });

    test('reads SEC1 keys too and signs deterministically', () {
      final fromSec1 = AppleJwtSigner(
        teamId: 'ABCDE12345',
        keyId: 'KEY1234567',
        privateKeyPem: sec1(appleKey),
        clock: () => now,
      );
      expect(fromSec1.sign(), signer().sign());
    });

    test('reuses a token, then makes a new one', () {
      var time = now;
      final jwt = signer(clock: () => time);
      final first = jwt.token();
      time = time.add(const Duration(minutes: 10));
      expect(jwt.token(), first);
      time = time.add(const Duration(minutes: 25));
      final second = jwt.token();
      expect(second, isNot(first));
      expect(
        _jwtPart(second.split('.')[1])['iat'],
        time.millisecondsSinceEpoch ~/ 1000,
      );
    });

    test('rejects what is not a P-256 private key', () {
      for (final pem in [
        'not a key',
        _pem('PRIVATE KEY', [0, 0, 0]),
        _pem(
          'PRIVATE KEY',
          DerWriter.sequence([
            DerWriter.integer(0),
            DerWriter.sequence([
              DerWriter.oid(_ecPublicKey),
              DerWriter.oid('1.3.132.0.34'),
            ]),
            DerWriter.octets(DerWriter.sequence([DerWriter.integer(1)])),
          ]),
        ),
      ]) {
        expect(
          () => AppleJwtSigner(teamId: 't', keyId: 'k', privateKeyPem: pem),
          throwsFormatException,
          reason: pem,
        );
      }
    });
  });

  group('DeviceCheckClient', () {
    DeviceCheckClient client(
      FakeTransport transport, {
      AppleEnvironment environment = AppleEnvironment.production,
    }) => DeviceCheckClient(
      transport: transport,
      signer: signer(),
      environment: environment,
      clock: () => now,
      transactionIds: () => 'tx-1',
    );

    test('queries the bits with a signed request', () async {
      final transport = FakeTransport(
        (_) => _ok('{"bit0":true,"bit1":false,"last_update_time":"2026-09"}'),
      );
      final bits = await client(transport).queryTwoBits('dGVz\ndA==');
      expect(bits!.bit0, isTrue);
      expect(bits.bit1, isFalse);
      expect(bits.lastUpdateTime, '2026-09');
      final request = transport.last;
      expect(request.method, 'POST');
      expect(
        request.uri.toString(),
        'https://api.devicecheck.apple.com/v1/query_two_bits',
      );
      final authorization = request.headers['authorization']!;
      expect(authorization, startsWith('Bearer '));
      expect(
        _jwtVerifies(
          authorization.substring(7),
          EcPublicKey(_p256, appleKey.point),
        ),
        isTrue,
      );
      expect(jsonDecode(request.text), {
        'device_token': 'dGVzdA==',
        'transaction_id': 'tx-1',
        'timestamp': now.millisecondsSinceEpoch,
      });
    });

    test('returns null when Apple has no bits for the device', () async {
      final transport = FakeTransport((_) => _ok('Bit State Not Found'));
      expect(await client(transport).queryTwoBits('t'), isNull);
    });

    test('updates only the bits it is given', () async {
      final transport = FakeTransport((_) => _ok());
      await client(transport).updateTwoBits('t', bit1: true);
      expect(transport.last.uri.path, '/v1/update_two_bits');
      expect(jsonDecode(transport.last.text), {
        'device_token': 't',
        'transaction_id': 'tx-1',
        'timestamp': now.millisecondsSinceEpoch,
        'bit1': true,
      });
      expect(() => client(transport).updateTwoBits('t'), throwsArgumentError);
    });

    test('validates tokens and reports errors', () async {
      final transport = FakeTransport(
        (request) => jsonDecode(request.text)['device_token'] == 'good'
            ? _ok()
            : TransportResponse(
                statusCode: 400,
                body: utf8.encode('Missing or badly formatted device token'),
              ),
      );
      final devices = client(
        transport,
        environment: AppleEnvironment.development,
      );
      await devices.validateDeviceToken('good');
      expect(
        transport.last.uri.toString(),
        'https://api.development.devicecheck.apple.com/v1/validate_device_token',
      );
      expect(
        () => devices.validateDeviceToken('bad'),
        throwsA(
          isA<ApiException>()
              .having((e) => e.statusCode, 'statusCode', 400)
              .having((e) => e.body, 'body', contains('device token')),
        ),
      );
      expect(
        () => client(FakeTransport((_) => _ok('<html>'))).queryTwoBits('t'),
        throwsA(isA<ApiException>()),
      );
    });

    test('makes a new version 4 UUID for each transaction', () async {
      final transport = FakeTransport((_) => _ok());
      final devices = DeviceCheckClient(transport: transport, signer: signer());
      await devices.validateDeviceToken('a');
      await devices.validateDeviceToken('b');
      final ids = [
        for (final request in transport.requests)
          jsonDecode(request.text)['transaction_id'] as String,
      ];
      for (final id in ids) {
        expect(
          id,
          matches(
            RegExp(
              r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
            ),
          ),
        );
      }
      expect(ids.toSet(), hasLength(2));
    });
  });

  group('AppAttestReceiptReader', () {
    final receipts = FakeReceiptSigner();
    final attested = TestKey.generate(random);
    final attestedCertificate = testCertificate(
      serial: 99,
      issuer: 'Test App Attestation CA 1',
      subject: 'key',
      subjectSpki: attested.spki,
      signer: attested,
    );
    Map<int, Object> fields({DateTime? created}) => {
      2: 'ABCDE12345.com.example.app',
      3: attestedCertificate,
      4: Uint8List.fromList(List.filled(32, 4)),
      5: 'token',
      6: 'RECEIPT',
      12: (created ?? now).toIso8601String(),
      17: '5',
      19: '2026-10-15T12:00:00.000Z',
      21: '2027-01-12T12:00:00.000Z',
    };
    AppAttestReceiptReader reader({DateTime? at}) => AppAttestReceiptReader(
      trustedRoots: receipts.roots,
      clock: () => at ?? now,
    );

    test('reads a receipt signed directly or through attributes', () {
      for (final attributes in [false, true]) {
        final read = reader().read(
          receipts.receipt(fields(), signedAttributes: attributes),
          appId: 'ABCDE12345.com.example.app',
          publicKey: attested.point,
          maxAge: const Duration(minutes: 5),
        );
        expect(read.type, AppAttestReceiptType.receipt);
        expect(read.riskMetric, 5);
        expect(read.createdAt, now);
        expect(read.notBefore, DateTime.utc(2026, 10, 15, 12));
        expect(read.expiresAt, DateTime.utc(2027, 1, 12, 12));
        expect(read.token, 'token');
        expect(read.clientHash, List.filled(32, 4));
        expect(read.attestedPublicKey, attested.point);
      }
    });

    test('rejects a forged, changed, untrusted or expired receipt', () {
      Matcher invalid() => throwsA(isA<InvalidReceiptException>());
      expect(
        () => reader().read(
          receipts.receipt(fields(), signWith: TestKey.generate(random)),
        ),
        invalid(),
      );
      for (final attributes in [false, true]) {
        final changed = receipts.receipt(
          fields(),
          signedAttributes: attributes,
        );
        final at = String.fromCharCodes(changed).indexOf('RECEIPT');
        changed[at] = 'X'.codeUnitAt(0);
        expect(() => reader().read(changed), invalid());
      }
      expect(
        () => AppAttestReceiptReader(
          clock: () => now,
        ).read(receipts.receipt(fields())),
        invalid(),
      );
      expect(
        () => reader(at: DateTime.utc(2028)).read(receipts.receipt(fields())),
        invalid(),
      );
      expect(
        () => reader().read(receipts.receipt({...fields()}..remove(12))),
        invalid(),
      );
      expect(
        () => reader().read(
          receipts.receipt(
            fields(created: now.subtract(const Duration(minutes: 10))),
          ),
          maxAge: const Duration(minutes: 5),
        ),
        invalid(),
      );
    });
  });

  group('AppAttestReceiptClient', () {
    final receipts = FakeReceiptSigner();
    final fresh = receipts.receipt({
      2: 'ABCDE12345.com.example.app',
      6: 'RECEIPT',
      12: now.subtract(const Duration(minutes: 1)).toIso8601String(),
      17: '2',
    });

    AppAttestReceiptClient client(
      FakeTransport transport, {
      AppleEnvironment environment = AppleEnvironment.production,
    }) => AppAttestReceiptClient(
      transport: transport,
      signer: signer(),
      environment: environment,
      reader: AppAttestReceiptReader(
        trustedRoots: receipts.roots,
        clock: () => now,
      ),
    );

    test('exchanges a receipt for one with a risk metric', () async {
      final transport = FakeTransport((_) => _ok(base64.encode(fresh)));
      final old = Uint8List.fromList([1, 2, 3]);
      final receipt = await client(
        transport,
      ).refresh(old, appId: 'ABCDE12345.com.example.app');
      expect(receipt!.riskMetric, 2);
      expect(receipt.bytes, fresh);
      final request = transport.last;
      expect(
        request.uri.toString(),
        'https://data.appattest.apple.com/v1/attestationData',
      );
      expect(request.text, base64.encode(old));
      final token = request.headers['authorization']!;
      expect(token, isNot(startsWith('Bearer')));
      expect(_jwtVerifies(token, EcPublicKey(_p256, appleKey.point)), isTrue);
    });

    test('uses the development server for development keys', () async {
      final transport = FakeTransport((_) => _ok(base64.encode(fresh)));
      await client(
        transport,
        environment: AppleEnvironment.development,
      ).refresh(Uint8List(1));
      expect(transport.last.uri.host, 'data-development.appattest.apple.com');
    });

    test('returns null on 304 and throws on errors', () async {
      expect(
        await client(
          FakeTransport((_) => TransportResponse(statusCode: 304)),
        ).refresh(Uint8List(1)),
        isNull,
      );
      expect(
        () => client(
          FakeTransport(
            (_) => TransportResponse(
              statusCode: 401,
              body: utf8.encode('Unauthorized'),
            ),
          ),
        ).refresh(Uint8List(1)),
        throwsA(isA<ApiException>().having((e) => e.statusCode, 'status', 401)),
      );
      expect(
        () => client(FakeTransport((_) => _ok('%%%'))).refresh(Uint8List(1)),
        throwsA(isA<InvalidReceiptException>()),
      );
      expect(
        () => client(
          FakeTransport((_) => _ok(base64.encode(fresh))),
        ).refresh(Uint8List(1), appId: 'ABCDE12345.com.other'),
        throwsA(isA<InvalidReceiptException>()),
      );
    });

    test("reads Apple's own BER receipt", () async {
      final apple = verifierReceipt(base64.decode(appleSampleAttestation));
      final receipt = await AppAttestReceiptClient(
        transport: FakeTransport((_) => _ok(base64.encode(apple))),
        signer: signer(),
        reader: AppAttestReceiptReader(
          clock: () => DateTime.utc(2026, 4, 21, 18, 15),
        ),
      ).refresh(apple, appId: appleSampleAppId);
      expect(receipt!.type, AppAttestReceiptType.attest);
    });
  });

  group('PlayIntegrityClient', () {
    var tokens = 0;
    PlayIntegrityClient client(FakeTransport transport) => PlayIntegrityClient(
      transport: transport,
      accessToken: () async => 'ya29.token-${++tokens}',
    );

    test('decodes a token', () async {
      final transport = FakeTransport(
        (_) => _ok(
          jsonEncode({
            'tokenPayloadExternal': {
              'accountDetails': {'appLicensingVerdict': 'LICENSED'},
            },
          }),
        ),
      );
      final payload = await client(transport).decodeIntegrityToken(
        packageName: 'com.example.app',
        integrityToken: 'abc',
      );
      expect(
        PlayIntegrityVerdict.fromJson(
          payload,
        ).accountDetails.appLicensingVerdict,
        AppLicensingVerdict.licensed,
      );
      final request = transport.last;
      expect(
        request.uri.toString(),
        'https://playintegrity.googleapis.com/v1/com.example.app:decodeIntegrityToken',
      );
      expect(
        request.headers['authorization'],
        startsWith('Bearer ya29.token-'),
      );
      expect(jsonDecode(request.text), {'integrityToken': 'abc'});
    });

    test('writes device recall bits', () async {
      final transport = FakeTransport((_) => _ok('{}'));
      await client(transport).writeDeviceRecall(
        packageName: 'com.example.app',
        integrityToken: 'abc',
        newValues: const DeviceRecallValues(bitFirst: true, bitThird: false),
      );
      final request = transport.last;
      expect(request.method, 'POST');
      expect(
        request.uri.toString(),
        'https://playintegrity.googleapis.com/v1/com.example.app/deviceRecall:write',
      );
      expect(jsonDecode(request.text), {
        'integrityToken': 'abc',
        'newValues': {'bitFirst': true, 'bitThird': false},
      });
    });

    test('asks for a new access token for each request', () async {
      final transport = FakeTransport((_) => _ok('{}'));
      final play = client(transport);
      for (var i = 0; i < 2; i++) {
        await play.writeDeviceRecall(
          packageName: 'com.example.app',
          integrityToken: 'abc',
          newValues: const DeviceRecallValues(bitSecond: true),
        );
      }
      expect(
        transport.requests.map((r) => r.headers['authorization']).toSet(),
        hasLength(2),
      );
    });

    test('reports errors and refuses bad arguments', () async {
      final refusing = client(
        FakeTransport(
          (_) => TransportResponse(
            statusCode: 403,
            body: utf8.encode(
              '{"error":{"code":403,"status":"PERMISSION_DENIED"}}',
            ),
          ),
        ),
      );
      expect(
        () => refusing.decodeIntegrityToken(
          packageName: 'com.example.app',
          integrityToken: 'abc',
        ),
        throwsA(isA<ApiException>().having((e) => e.statusCode, 'status', 403)),
      );
      final play = client(FakeTransport((_) => _ok('{}')));
      expect(
        () => play.writeDeviceRecall(
          packageName: 'com.example.app',
          integrityToken: 'abc',
          newValues: const DeviceRecallValues(),
        ),
        throwsArgumentError,
      );
      expect(
        () => play.decodeIntegrityToken(
          packageName: 'com.example.app/../x',
          integrityToken: 'abc',
        ),
        throwsArgumentError,
      );
      expect(
        () => play.decodeIntegrityToken(
          packageName: 'com.example.app',
          integrityToken: 'abc',
        ),
        throwsA(isA<ApiException>()),
        reason: 'no tokenPayloadExternal',
      );
    });
  });

  group('IoHttpTransport', () {
    late HttpServer server;

    setUp(() async {
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((request) async {
        final body = await utf8.decodeStream(request);
        request.response
          ..statusCode = request.uri.path == '/big' ? 200 : 201
          ..headers.set('X-Echo', request.headers.value('authorization') ?? '')
          ..write(
            request.uri.path == '/big'
                ? 'x' * 5000
                : '${request.method} ${request.uri.path} $body',
          );
        await request.response.close();
      });
    });

    tearDown(() => server.close(force: true));

    test('sends a request and reads the response', () async {
      final transport = IoHttpTransport();
      addTearDown(transport.close);
      final response = await transport.send(
        TransportRequest(
          method: 'POST',
          uri: Uri.parse('http://127.0.0.1:${server.port}/v1/echo'),
          headers: {'authorization': 'Bearer t'},
          body: utf8.encode('hello'),
        ),
      );
      expect(response.statusCode, 201);
      expect(response.text, 'POST /v1/echo hello');
      expect(response.headers['x-echo'], 'Bearer t');
    });

    test('refuses a response larger than its limit', () async {
      final transport = IoHttpTransport(maxResponseBytes: 1000);
      addTearDown(transport.close);
      expect(
        () => transport.send(
          TransportRequest(
            method: 'GET',
            uri: Uri.parse('http://127.0.0.1:${server.port}/big'),
          ),
        ),
        throwsA(isA<HttpException>()),
      );
    });
  });
}
