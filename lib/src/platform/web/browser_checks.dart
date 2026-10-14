import '../../scan_options.dart';
import '../../signal.dart';
import '../checks/signal_check.dart';

/// What the browser checks read from the page. The checks only see this port,
/// so tests give them a fake one.
abstract interface class BrowserEnvironment {
  /// `navigator.webdriver`: true while WebDriver (Selenium, Playwright,
  /// Puppeteer) controls the browser.
  bool get webdriver;

  String get userAgent;
}

/// The page is driven by browser automation instead of a person.
final class BrowserAutomationCheck implements SignalCheck {
  const BrowserAutomationCheck(this._browser);

  final BrowserEnvironment _browser;

  @override
  AntiVirtualSignal get signal => AntiVirtualSignal.automation;

  @override
  Future<SignalResult> run(ScanOptions options) async => resultOf([
    if (_browser.webdriver) 'browser controlled through WebDriver',
    if (_browser.userAgent.contains('HeadlessChrome')) 'headless Chrome',
  ]);
}
