/// Stands in for `dart:io`'s `exit` where there is no process to end (the
/// web). The guard never calls it there: on the web a block keeps the
/// blocking screen up instead of closing anything.
Never exit(int code) =>
    throw UnsupportedError('exit() is not available on this platform');
