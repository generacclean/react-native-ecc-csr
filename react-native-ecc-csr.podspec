require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

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

  # Swift (CSRModule, the Expo glue) and Objective-C (CSRCore) in one pod: DEFINES_MODULE makes
  # CocoaPods emit an umbrella header for CSRCore.h, which is how the Swift side sees it.
  s.source_files = "ios/**/*.{h,m,swift}"
  s.pod_target_xcconfig = {
    "DEFINES_MODULE" => "YES",
    "SWIFT_COMPILATION_MODE" => "wholemodule"
  }

  s.dependency "ExpoModulesCore"

  s.frameworks = "Security"
end
