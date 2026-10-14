/// Stands in for `dart:io`'s `exit` where there is no process to end (the
/// web). The guard only calls it after a block, which cannot happen there
/// because every check is unsupported.
Never exit(int code) =>
    throw UnsupportedError('exit() is not available on this platform');
