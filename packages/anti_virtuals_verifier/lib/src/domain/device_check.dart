/// The two bits Apple's DeviceCheck service keeps for a device and your
/// team.
final class DeviceCheckBits {
  const DeviceCheckBits({
    required this.bit0,
    required this.bit1,
    this.lastUpdateTime,
  });

  final bool bit0;
  final bool bit1;

  /// When the bits last changed, as `YYYY-MM`.
  final String? lastUpdateTime;

  @override
  String toString() =>
      'DeviceCheckBits(bit0: $bit0, bit1: $bit1, '
      'lastUpdateTime: $lastUpdateTime)';
}
