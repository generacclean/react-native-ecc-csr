require "json"

package = JSON.parse(File.read(File.join(__dir__, "..", "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-ecc-csr"
  s.version      = package["version"]
  s.summary      = package["description"] || "ECC CSR generation for React Native"
  s.homepage     = package["homepage"] || "https://github.com/generacclean/react-native-ecc-csr"
  s.authors      = package["author"] || { "Generac" => "developer@generac.com" }
  s.license      = package["license"] || "MIT"

  # 15.1 is the floor for the Expo SDK this module targets (expo-modules-core requires it).
  s.platforms    = { :ios => "15.1" }
  s.swift_version = "5.9"
  s.source       = { :git => "https://github.com/generacclean/react-native-ecc-csr.git", :tag => "#{s.version}" }
  s.static_framework = true

  # Lives in ios/ rather than the package root because that is where Expo autolinking looks for
  # podspecs, so paths here are relative to ios/.
  s.source_files = "**/*.swift"
  s.exclude_files = "Tests/**/*"
  s.pod_target_xcconfig = {
    "DEFINES_MODULE" => "YES"
  }

  s.dependency "ExpoModulesCore"

  s.frameworks = "Security"

  # XCTests for CSRCore. The Keychain only works for signed, hosted code, so they run inside the
  # app host CocoaPods generates. example/plugins/withLibraryTests.js enables this test spec.
  s.test_spec "Tests" do |test_spec|
    test_spec.source_files = "Tests/**/*.swift"
    test_spec.requires_app_host = true
  end
end
