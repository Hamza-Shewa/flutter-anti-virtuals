import 'dart:convert';
import 'dart:typed_data';

/// A CBOR tag (major type 6) and the item it wraps. The decoder does not
/// interpret tags.
final class CborTag {
  const CborTag(this.tag, this.value);

  final int tag;
  final Object? value;

  @override
  bool operator ==(Object other) =>
      other is CborTag && other.tag == tag && other.value == value;

  @override
  int get hashCode => Object.hash(tag, value);
}

/// The CBOR `undefined` simple value.
final class CborUndefined {
  const CborUndefined._();

  static const instance = CborUndefined._();
}

/// Decodes [data], which must hold exactly one CBOR item (RFC 8949).
///
/// Unsigned and negative integers become [int], byte strings [Uint8List],
/// text strings [String], arrays [List], maps [Map], `true`/`false`/`null`
/// themselves, floats [double], tags [CborTag]. Indefinite lengths are
/// supported. Throws [FormatException] on anything malformed, on integers
/// outside the 64-bit signed range and on duplicate map keys.
Object? decodeCbor(Uint8List data) {
  final (value, end) = readCbor(data);
  if (end != data.length) {
    throw const FormatException('Trailing bytes after the CBOR item');
  }
  return value;
}

/// Reads one CBOR item at [offset] and returns it with the offset after it.
(Object?, int) readCbor(Uint8List data, [int offset = 0]) {
  final reader = _Reader(data, offset);
  final value = reader.item(0);
  return (value, reader.offset);
}

final class _Reader {
  _Reader(this.data, this.offset);

  static const _maxDepth = 32;
  static const _break = _Break();

  final Uint8List data;
  int offset;

  int _byte() {
    if (offset >= data.length) throw const FormatException('Truncated CBOR');
    return data[offset++];
  }

  Uint8List _bytes(int length) {
    if (length < 0 || length > data.length - offset) {
      throw const FormatException('Truncated CBOR');
    }
    final bytes = Uint8List.fromList(data.sublist(offset, offset + length));
    offset += length;
    return bytes;
  }

  /// The argument of an initial byte. Null for an indefinite length.
  int? _argument(int info) {
    if (info < 24) return info;
    if (info == 31) return null;
    final size = switch (info) {
      24 => 1,
      25 => 2,
      26 => 4,
      27 => 8,
      _ => throw FormatException('Reserved CBOR additional info $info'),
    };
    final bytes = _bytes(size);
    if (size == 8 && bytes[0] & 0x80 != 0) {
      throw const FormatException('CBOR integer out of range');
    }
    var value = 0;
    for (final b in bytes) {
      value = (value << 8) | b;
    }
    return value;
  }

  int _length(int info) {
    final length = _argument(info);
    if (length == null) throw const FormatException('Unexpected CBOR break');
    return length;
  }

  Object? item(int depth) {
    if (depth > _maxDepth) throw const FormatException('CBOR nested too deep');
    final initial = _byte();
    final major = initial >> 5;
    final info = initial & 0x1f;
    switch (major) {
      case 0:
        return _length(info);
      case 1:
        return -1 - _length(info);
      case 2:
      case 3:
        final Uint8List bytes;
        if (info == 31) {
          final chunks = BytesBuilder(copy: false);
          while (true) {
            final next = _byte();
            if (next == 0xff) break;
            if (next >> 5 != major || next & 0x1f == 31) {
              throw const FormatException('Bad CBOR string chunk');
            }
            chunks.add(_bytes(_length(next & 0x1f)));
          }
          bytes = chunks.takeBytes();
        } else {
          bytes = _bytes(_length(info));
        }
        if (major == 2) return bytes;
        try {
          return utf8.decode(bytes);
        } on FormatException {
          throw const FormatException('CBOR text is not UTF-8');
        }
      case 4:
        final length = _argument(info);
        final items = <Object?>[];
        if (length == null) {
          while (true) {
            final value = _itemOrBreak(depth);
            if (identical(value, _break)) break;
            items.add(value);
          }
        } else {
          if (length > data.length - offset) {
            throw const FormatException('Truncated CBOR');
          }
          for (var i = 0; i < length; i++) {
            items.add(item(depth + 1));
          }
        }
        return List<Object?>.unmodifiable(items);
      case 5:
        final length = _argument(info);
        final map = <Object?, Object?>{};
        void put(Object? key) {
          if (map.containsKey(key)) {
            throw const FormatException('Duplicate CBOR map key');
          }
          map[key] = item(depth + 1);
        }

        if (length == null) {
          while (true) {
            final key = _itemOrBreak(depth);
            if (identical(key, _break)) break;
            put(key);
          }
        } else {
          if (length > data.length - offset) {
            throw const FormatException('Truncated CBOR');
          }
          for (var i = 0; i < length; i++) {
            put(item(depth + 1));
          }
        }
        return Map<Object?, Object?>.unmodifiable(map);
      case 6:
        return CborTag(_length(info), item(depth + 1));
      default:
        return _simple(info);
    }
  }

  Object? _itemOrBreak(int depth) {
    if (offset < data.length && data[offset] == 0xff) {
      offset++;
      return _break;
    }
    return item(depth + 1);
  }

  Object? _simple(int info) {
    switch (info) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
        return null;
      case 23:
        return CborUndefined.instance;
      case 25:
        return _half(_bytes(2));
      case 26:
        return ByteData.sublistView(_bytes(4)).getFloat32(0);
      case 27:
        return ByteData.sublistView(_bytes(8)).getFloat64(0);
      case 31:
        throw const FormatException('Unexpected CBOR break');
      default:
        throw FormatException('Unsupported CBOR simple value $info');
    }
  }

  static double _half(Uint8List bytes) {
    final half = (bytes[0] << 8) | bytes[1];
    final exponent = (half >> 10) & 0x1f;
    final mantissa = half & 0x3ff;
    final double value;
    if (exponent == 0) {
      value = mantissa * 5.9604644775390625e-8; // 2^-24
    } else if (exponent == 31) {
      value = mantissa == 0 ? double.infinity : double.nan;
    } else {
      value = (1 + mantissa / 1024) * _pow2(exponent - 15);
    }
    return half & 0x8000 != 0 ? -value : value;
  }

  static double _pow2(int exponent) {
    var value = 1.0;
    for (var i = 0; i < exponent.abs(); i++) {
      value = exponent < 0 ? value / 2 : value * 2;
    }
    return value;
  }
}

final class _Break {
  const _Break();
}
