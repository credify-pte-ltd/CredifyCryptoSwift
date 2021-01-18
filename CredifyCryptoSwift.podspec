#
#  Be sure to run `pod spec lint CredifyCryptoSwift.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see https://guides.cocoapods.org/syntax/podspec.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |spec|
  spec.name = "CredifyCryptoSwift"
  spec.version = "1.0.11"
  spec.summary = "Credify crypto related framework in Swift"
  spec.description = "Cryptography functions and helpers for Swift. Ed25519 signing, RSA encryption. With PKCS#8 format."
  spec.homepage = "https://github.com/credify-pte-ltd/CredifyCryptoSwift"
  spec.license = { type: 'MIT', file: 'LICENSE' }
  spec.authors = { "Shuichi Nagao" => 'shu@credify.one' }
  spec.social_media_url = "https://credify.one"
  spec.swift_version = "5.3"
  spec.platform = :ios, "12.0"
  spec.source = { git: "https://github.com/credify-pte-ltd/CredifyCryptoSwift.git", tag: "v#{spec.version}" }
  # spec.source_files = "CredifyCryptoSwift/**/*.{h,swift}", "CredifyCryptoSwift/Crypto.framework"
  spec.source_files = "CredifyCryptoSwift/**/*.{h,swift}"
  # spec.ios.public_header_files = "CredifyCryptoSwift/Crypto.framework/Versions/A/Headers/*.h"
  spec.vendored_frameworks = "CredifyCryptoSwift/Crypto.framework"

end
