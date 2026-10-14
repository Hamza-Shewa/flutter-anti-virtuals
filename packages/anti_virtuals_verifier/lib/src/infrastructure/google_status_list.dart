import '../domain/ports.dart';

/// Google's attestation certificate status list, from
/// https://android.googleapis.com/attestation/status.
///
/// Fetch it on your server, cache it (it changes rarely, typically a few
/// times a year) and build this from the decoded JSON.
final class GoogleStatusList implements RevocationList {
  GoogleStatusList(Map<String, Object?> json)
    : _entries = {
        for (final key
            in (json['entries'] as Map<String, Object?>? ?? const {}).keys)
          key.toLowerCase(),
      };

  final Set<String> _entries;

  /// Every listed certificate counts as revoked. The list keys most serials
  /// as lowercase hex but some as decimal, so both forms are looked up.
  @override
  bool isRevoked(BigInt serialNumber) =>
      _entries.contains(serialNumber.toRadixString(16)) ||
      _entries.contains(serialNumber.toString());
}
