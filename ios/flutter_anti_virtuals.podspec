#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint flutter_anti_virtuals.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'flutter_anti_virtuals'
  s.version          = '0.2.0'
  s.summary          = "Detects VPNs, proxies, mock location, virtual cameras and tampered environments."
  s.description      = <<-DESC
Integrity signal scanner for Flutter apps.
                       DESC
  s.homepage         = 'https://github.com/Hamza-Shewa/flutter-anti-virtuals'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Hamza Shewa' => 'shewa.hz98@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'flutter_anti_virtuals/Sources/flutter_anti_virtuals/**/*.swift'
  s.dependency 'Flutter'
  s.platform = :ios, '15.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # Declares the required-reason APIs the plugin uses (UserDefaults).
  s.resource_bundles = {'flutter_anti_virtuals_privacy' => ['flutter_anti_virtuals/Sources/flutter_anti_virtuals/PrivacyInfo.xcprivacy']}
end
