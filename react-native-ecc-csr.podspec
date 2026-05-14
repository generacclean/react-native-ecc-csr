require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-ecc-csr"
  s.version      = package["version"]
  s.summary      = package["description"] || "ECC CSR generation for React Native"
  s.homepage     = package["homepage"] || "https://github.com/generacclean/react-native-ecc-csr"
  s.authors      = package["author"] || { "Generac" => "developer@generac.com" }
  s.license      = package["license"] || "MIT"

  s.platforms    = { :ios => "12.0" }
  s.source       = { :git => "https://github.com/generacclean/react-native-ecc-csr.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm}"

  s.dependency "React-Core"
  
  s.frameworks = "Security"
end
