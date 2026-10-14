import 'dart:convert';
import 'dart:typed_data';

/// A minimal DER encoder for building test certificates.
abstract final class DerWriter {
  static Uint8List element(
    int tagClass,
    bool constructed,
    int tag,
    List<int> content,
  ) {
    final out = BytesBuilder();
    final head = (tagClass << 6) | (constructed ? 0x20 : 0);
    if (tag < 0x1f) {
      out.addByte(head | tag);
    } else {
      out.addByte(head | 0x1f);
      final groups = <int>[];
      var t = tag;
      do {
        groups.insert(0, t & 0x7f);
        t >>= 7;
      } while (t > 0);
      for (var i = 0; i < groups.length; i++) {
        out.addByte(groups[i] | (i < groups.length - 1 ? 0x80 : 0));
      }
    }
    final length = content.length;
    if (length < 0x80) {
      out.addByte(length);
    } else {
      final bytes = <int>[];
      for (var l = length; l > 0; l >>= 8) {
        bytes.insert(0, l & 0xff);
      }
      out.addByte(0x80 | bytes.length);
      out.add(bytes);
    }
    out.add(content);
    return out.toBytes();
  }

  static Uint8List universal(
    int tag,
    List<int> content, {
    bool constructed = false,
  }) => element(0, constructed, tag, content);

  static Uint8List sequence(List<List<int>> items) =>
      universal(16, items.expand((e) => e).toList(), constructed: true);

  static Uint8List set(List<List<int>> items) =>
      universal(17, items.expand((e) => e).toList(), constructed: true);

  static Uint8List explicit(int tag, List<int> inner) =>
      element(2, true, tag, inner);

  static Uint8List integer(Object value) {
    var v = value is BigInt ? value : BigInt.from(value as int);
    final bytes = <int>[];
    if (v == BigInt.zero) bytes.add(0);
    while (v > BigInt.zero) {
      bytes.insert(0, (v & BigInt.from(0xff)).toInt());
      v >>= 8;
    }
    if (bytes.first & 0x80 != 0) bytes.insert(0, 0);
    return universal(2, bytes);
  }

  static Uint8List enumerated(int value) =>
      universal(10, integer(value).sublist(2));

  static Uint8List boolean(bool value) => universal(1, [value ? 0xff : 0]);

  static Uint8List nullValue() => universal(5, const []);

  static Uint8List octets(List<int> bytes) => universal(4, bytes);

  static Uint8List bitString(List<int> bytes) => universal(3, [0, ...bytes]);

  static Uint8List utf8String(String text) => universal(12, utf8.encode(text));

  static Uint8List utcTime(DateTime time) {
    String two(int n) => n.toString().padLeft(2, '0');
    final t = time.toUtc();
    return universal(
      23,
      ascii.encode(
        '${two(t.year % 100)}${two(t.month)}${two(t.day)}'
        '${two(t.hour)}${two(t.minute)}${two(t.second)}Z',
      ),
    );
  }

  static Uint8List oid(String dotted) {
    final parts = dotted.split('.').map(int.parse).toList();
    final bytes = <int>[parts[0] * 40 + parts[1]];
    for (final part in parts.skip(2)) {
      final groups = <int>[];
      var p = part;
      do {
        groups.insert(0, p & 0x7f);
        p >>= 7;
      } while (p > 0);
      for (var i = 0; i < groups.length; i++) {
        bytes.add(groups[i] | (i < groups.length - 1 ? 0x80 : 0));
      }
    }
    return universal(6, bytes);
  }
}
