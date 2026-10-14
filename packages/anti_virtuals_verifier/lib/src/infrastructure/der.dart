import 'dart:typed_data';

/// One DER element. Only what X.509 and Android key attestation need: definite
/// lengths, high tag numbers, and the primitive types read below.
final class Der {
  Der._(
    this._data,
    this._headerStart,
    this.tagClass,
    this.constructed,
    this.tag,
    this._start,
    this._end,
  );

  /// Reads the element at [offset] in [data]. Throws [FormatException] on
  /// anything that is not well formed DER.
  factory Der.read(Uint8List data, [int offset = 0]) {
    var i = offset;
    int next() {
      if (i >= data.length) throw const FormatException('Truncated DER');
      return data[i++];
    }

    final first = next();
    final tagClass = first >> 6;
    final constructed = first & 0x20 != 0;
    var tag = first & 0x1f;
    if (tag == 0x1f) {
      tag = 0;
      int b;
      do {
        b = next();
        tag = (tag << 7) | (b & 0x7f);
        if (tag > 0x1fffff) throw const FormatException('DER tag too large');
      } while (b & 0x80 != 0);
    }
    var length = next();
    if (length == 0x80) {
      throw const FormatException('Indefinite DER length');
    }
    if (length > 0x80) {
      final count = length & 0x7f;
      if (count > 4) throw const FormatException('DER length too large');
      length = 0;
      for (var n = 0; n < count; n++) {
        length = (length << 8) | next();
      }
    }
    final end = i + length;
    if (end > data.length) throw const FormatException('Truncated DER');
    return Der._(data, offset, tagClass, constructed, tag, i, end);
  }

  /// Parses [data], which must hold exactly one element.
  factory Der.parse(Uint8List data) {
    final element = Der.read(data);
    if (element.encodedEnd != data.length) {
      throw const FormatException('Trailing bytes after DER element');
    }
    return element;
  }

  static const universal = 0;
  static const contextSpecific = 2;

  static const tagBoolean = 1;
  static const tagInteger = 2;
  static const tagBitString = 3;
  static const tagOctetString = 4;
  static const tagOid = 6;
  static const tagEnumerated = 10;
  static const tagSequence = 16;
  static const tagSet = 17;
  static const tagUtcTime = 23;
  static const tagGeneralizedTime = 24;

  final Uint8List _data;
  final int _headerStart;
  final int tagClass;
  final bool constructed;
  final int tag;
  final int _start;
  final int _end;

  /// Where the next element after this one starts.
  int get encodedEnd => _end;

  /// The content octets.
  Uint8List get content => Uint8List.sublistView(_data, _start, _end);

  /// The whole encoding, header included.
  Uint8List get encoded => Uint8List.sublistView(_data, _headerStart, _end);

  bool isUniversal(int universalTag) =>
      tagClass == universal && tag == universalTag;

  bool isContext(int contextTag) =>
      tagClass == contextSpecific && tag == contextTag;

  /// The elements inside a constructed element.
  late final List<Der> children = () {
    if (!constructed) throw const FormatException('Not a constructed element');
    final out = <Der>[];
    var offset = _start;
    while (offset < _end) {
      final child = Der.read(_data, offset);
      if (child.encodedEnd > _end) {
        throw const FormatException('DER child overruns its parent');
      }
      out.add(child);
      offset = child.encodedEnd;
    }
    return List<Der>.unmodifiable(out);
  }();

  Der _expect(int universalTag) {
    if (!isUniversal(universalTag)) {
      throw FormatException('Expected DER tag $universalTag, found $tag');
    }
    return this;
  }

  List<Der> get sequence => _expect(tagSequence).children;
  List<Der> get set => _expect(tagSet).children;

  BigInt get integer => _signed(_expect(tagInteger).content);

  int get enumerated => _signed(_expect(tagEnumerated).content).toInt();

  bool get boolean {
    final bytes = _expect(tagBoolean).content;
    if (bytes.length != 1) throw const FormatException('Bad DER boolean');
    return bytes[0] != 0;
  }

  Uint8List get octets => _expect(tagOctetString).content;

  /// The bits of a BIT STRING, which must be a whole number of bytes.
  Uint8List get bits {
    final bytes = _expect(tagBitString).content;
    if (bytes.isEmpty || bytes[0] != 0) {
      throw const FormatException('Unsupported DER bit string');
    }
    return Uint8List.sublistView(bytes, 1);
  }

  String get oid {
    final bytes = _expect(tagOid).content;
    if (bytes.isEmpty) throw const FormatException('Empty DER OID');
    final parts = <int>[];
    var value = 0;
    for (final b in bytes) {
      value = (value << 7) | (b & 0x7f);
      if (b & 0x80 == 0) {
        parts.add(value);
        value = 0;
      }
    }
    final first = parts.first;
    final head = first < 40
        ? [0, first]
        : first < 80
        ? [1, first - 40]
        : [2, first - 80];
    return [...head, ...parts.skip(1)].join('.');
  }

  DateTime get time {
    final text = String.fromCharCodes(content);
    if (isUniversal(tagUtcTime)) {
      final m = RegExp(
        r'^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$',
      ).firstMatch(text);
      if (m == null) throw FormatException('Bad UTCTime $text');
      final yy = int.parse(m[1]!);
      return DateTime.utc(
        yy < 50 ? 2000 + yy : 1900 + yy,
        int.parse(m[2]!),
        int.parse(m[3]!),
        int.parse(m[4]!),
        int.parse(m[5]!),
        int.parse(m[6]!),
      );
    }
    if (isUniversal(tagGeneralizedTime)) {
      final m = RegExp(
        r'^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$',
      ).firstMatch(text);
      if (m == null) throw FormatException('Bad GeneralizedTime $text');
      return DateTime.utc(
        int.parse(m[1]!),
        int.parse(m[2]!),
        int.parse(m[3]!),
        int.parse(m[4]!),
        int.parse(m[5]!),
        int.parse(m[6]!),
      );
    }
    throw FormatException('Expected a DER time, found tag $tag');
  }

  static BigInt _signed(Uint8List bytes) {
    if (bytes.isEmpty) throw const FormatException('Empty DER integer');
    var value = BigInt.zero;
    for (final b in bytes) {
      value = (value << 8) | BigInt.from(b);
    }
    if (bytes[0] & 0x80 != 0) value -= BigInt.one << (bytes.length * 8);
    return value;
  }
}

/// Reads a non-negative big-endian integer, as used for EC coordinates.
BigInt unsignedBigInt(List<int> bytes) {
  var value = BigInt.zero;
  for (final b in bytes) {
    value = (value << 8) | BigInt.from(b);
  }
  return value;
}

/// Runs [parse] and reports any failure as a [FormatException], so callers
/// only have one kind of error to handle for untrusted input.
T parseOrFormatException<T>(String what, T Function() parse) {
  try {
    return parse();
  } on FormatException {
    rethrow;
  } catch (e) {
    throw FormatException('Malformed $what ($e)');
  }
}
