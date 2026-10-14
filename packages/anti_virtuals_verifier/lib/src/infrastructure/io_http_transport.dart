import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../domain/ports.dart';

/// An [HttpTransport] on `dart:io`'s [HttpClient].
final class IoHttpTransport implements HttpTransport {
  IoHttpTransport({
    HttpClient? client,
    this.timeout = const Duration(seconds: 30),
    this.maxResponseBytes = 1 << 20,
  }) : _client = client ?? HttpClient();

  final HttpClient _client;

  /// How long a request may take, from connecting to the last byte.
  final Duration timeout;

  /// Larger responses fail with an [HttpException]. Apple's and Google's
  /// answers are a few kilobytes.
  final int maxResponseBytes;

  @override
  Future<TransportResponse> send(TransportRequest request) =>
      _send(request).timeout(timeout);

  Future<TransportResponse> _send(TransportRequest request) async {
    final outgoing = await _client.openUrl(request.method, request.uri);
    request.headers.forEach(outgoing.headers.set);
    outgoing.contentLength = request.body.length;
    outgoing.add(request.body);
    final response = await outgoing.close();
    final body = BytesBuilder(copy: false);
    await for (final chunk in response) {
      body.add(chunk);
      if (body.length > maxResponseBytes) {
        throw HttpException('Response too large', uri: request.uri);
      }
    }
    final headers = <String, String>{};
    response.headers.forEach(
      (name, values) => headers[name.toLowerCase()] = values.join(', '),
    );
    return TransportResponse(
      statusCode: response.statusCode,
      body: body.takeBytes(),
      headers: headers,
    );
  }

  /// Closes the underlying client.
  void close({bool force = false}) => _client.close(force: force);
}
