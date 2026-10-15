import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/src/platform/web/browser_checks.dart';
import 'package:flutter_test/flutter_test.dart';

class _FakeBrowser implements BrowserEnvironment {
  const _FakeBrowser({this.webdriver = false, this.userAgent = 'Mozilla/5.0'});

  @override
  final bool webdriver;

  @override
  final String userAgent;
}

void main() {
  test('a person browsing is not automation', () async {
    final result = await const BrowserAutomationCheck(
      _FakeBrowser(),
    ).run(ScanOptions());
    expect(result.detected, isFalse);
    expect(result.supported, isTrue);
  });

  test('WebDriver and headless Chrome are automation', () async {
    final result = await const BrowserAutomationCheck(
      _FakeBrowser(
        webdriver: true,
        userAgent: 'Mozilla/5.0 HeadlessChrome/140.0.0.0',
      ),
    ).run(ScanOptions());
    expect(result.details, [
      'browser controlled through WebDriver',
      'headless Chrome',
    ]);
  });

  test('the check answers the automation signal', () {
    expect(
      const BrowserAutomationCheck(_FakeBrowser()).signal,
      AntiVirtualSignal.automation,
    );
  });
}
