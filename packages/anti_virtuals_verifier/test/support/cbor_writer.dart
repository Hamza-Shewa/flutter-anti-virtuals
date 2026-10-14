import 'dart:convert';
import 'dart:typed_data';

/// A minimal CBOR encoder (definite lengths) for building test objects.
abstract final class CborWriter {
  static Uint8List encode(Object? value) {
    final out = BytesBuilder();
    _write(out, value);
    return out.toBytes();
  }

  static void _head(BytesBuilder out, int major, int value) {
    if (value < 24) {
      out.addByte((major << 5) | value);
    } else if (value < 0x100) {
      out
        ..addByte((major << 5) | 24)
        ..addByte(value);
    } else if (value < 0x10000) {
      out
        ..addByte((major << 5) | 25)
        ..add([value >> 8, value & 0xff]);
    } else if (value < 0x100000000) {
      out
        ..addByte((major << 5) | 26)
        ..add([
          for (var shift = 24; shift >= 0; shift -= 8) (value >> shift) & 0xff,
        ]);
    } else {
      out
        ..addByte((major << 5) | 27)
        ..add([
          for (var shift = 56; shift >= 0; shift -= 8) (value >> shift) & 0xff,
        ]);
    }
  }

  static void _write(BytesBuilder out, Object? value) {
    switch (value) {
      case null:
        out.addByte(0xf6);
      case false:
        out.addByte(0xf4);
      case true:
        out.addByte(0xf5);
      case final int number when number >= 0:
        _head(out, 0, number);
      case final int number:
        _head(out, 1, -1 - number);
      case final Uint8List bytes:
        _head(out, 2, bytes.length);
        out.add(bytes);
      case final String text:
        final bytes = utf8.encode(text);
        _head(out, 3, bytes.length);
        out.add(bytes);
      case final List<Object?> items:
        _head(out, 4, items.length);
        for (final item in items) {
          _write(out, item);
        }
      case final Map<Object?, Object?> map:
        _head(out, 5, map.length);
        for (final MapEntry(:key, :value) in map.entries) {
          _write(out, key);
          _write(out, value);
        }
      default:
        throw ArgumentError('Cannot encode $value');
    }
  }
}
