import 'dart:typed_data';

import 'package:anti_virtuals_verifier/src/infrastructure/cbor.dart';
import 'package:test/test.dart';

import 'support/cbor_writer.dart';

Uint8List _hex(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

void main() {
  group('decodeCbor', () {
    test('reads the examples of RFC 8949 appendix A', () {
      final examples = <String, Object?>{
        '00': 0,
        '17': 23,
        '1818': 24,
        '1903e8': 1000,
        '1a000f4240': 1000000,
        '1b000000e8d4a51000': 1000000000000,
        '20': -1,
        '3863': -100,
        '3903e7': -1000,
        'f90000': 0.0,
        'f93c00': 1.0,
        'f97bff': 65504.0,
        'f90001': 5.960464477539063e-8,
        'f9c400': -4.0,
        'fa47c35000': 100000.0,
        'fb3ff199999999999a': 1.1,
        'f4': false,
        'f5': true,
        'f6': null,
        '60': '',
        '6161': 'a',
        '6449455446': 'IETF',
        '62c3bc': 'ü',
        '80': <Object?>[],
        '83010203': [1, 2, 3],
        '8301820203820405': [
          1,
          [2, 3],
          [4, 5],
        ],
        'a0': <Object?, Object?>{},
        'a201020304': {1: 2, 3: 4},
        'a26161016162820203': {
          'a': 1,
          'b': [2, 3],
        },
        '7f657374726561646d696e67ff': 'streaming',
        '9fff': <Object?>[],
        '9f018202039f0405ffff': [
          1,
          [2, 3],
          [4, 5],
        ],
        'bf61610161629f0203ffff': {
          'a': 1,
          'b': [2, 3],
        },
      };
      for (final MapEntry(:key, :value) in examples.entries) {
        expect(decodeCbor(_hex(key)), value, reason: key);
      }
      expect(decodeCbor(_hex('f97c00')), double.infinity);
      expect((decodeCbor(_hex('f97e00')) as double).isNaN, isTrue);
      expect(decodeCbor(_hex('f7')), CborUndefined.instance);
    });

    test('reads byte strings, also in chunks', () {
      expect(decodeCbor(_hex('4401020304')), [1, 2, 3, 4]);
      expect(decodeCbor(_hex('4401020304')), isA<Uint8List>());
      expect(decodeCbor(_hex('5f42010243030405ff')), [1, 2, 3, 4, 5]);
    });

    test('keeps tags', () {
      expect(
        decodeCbor(_hex('c074323031332d30332d32315432303a30343a30305a')),
        const CborTag(0, '2013-03-21T20:04:00Z'),
      );
    });

    test('round-trips what the test writer encodes', () {
      final value = {
        'fmt': 'apple-appattest',
        'attStmt': {
          'x5c': [
            Uint8List.fromList([1, 2]),
          ],
          'receipt': Uint8List(300),
        },
        -2: Uint8List.fromList(List.filled(32, 7)),
        70000: -70000,
        'big': 1 << 40,
      };
      expect(decodeCbor(CborWriter.encode(value)), value);
    });

    test('readCbor returns where the item ends', () {
      final data = Uint8List.fromList([
        ...CborWriter.encode({1: 2}),
        ...CborWriter.encode('next'),
      ]);
      final (first, end) = readCbor(data);
      expect(first, {1: 2});
      expect(readCbor(data, end).$1, 'next');
    });

    test('rejects malformed input with a FormatException only', () {
      for (final hex in [
        '', // empty
        '18', // missing argument
        '1c', // reserved additional info
        '62c3', // truncated text
        '6280ff', // invalid UTF-8
        '83 0102'.replaceAll(' ', ''), // truncated array
        'a20102', // truncated map
        'a201020103', // duplicate key
        '0001', // trailing bytes
        'ff', // break outside indefinite item
        '1bffffffffffffffff', // above the 64-bit signed range
        '5f6161ff', // text chunk in a byte string
        'f8ff', // unsupported simple value
        '9a7fffffff', // array longer than the input
      ]) {
        expect(() => decodeCbor(_hex(hex)), throwsFormatException, reason: hex);
      }
      final deep = Uint8List.fromList([...List.filled(100, 0x81), 0x00]);
      expect(() => decodeCbor(deep), throwsFormatException);
    });
  });
}
