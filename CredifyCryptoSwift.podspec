Pod::Spec.new do |spec|
  spec.name = "CredifyCryptoSwift"
  spec.version = "1.0.0"
  spec.summary = "Credify crypto related framework"
  spec.homepage = "https://github.com/credify-pte-ltd/Credify-Crypto-Swift"
  spec.license = { type: 'MIT', file: 'LICENSE' }
  spec.authors = { "Credify Pte. Ltd." => 'info@credify.one' }
  spec.social_media_url = "https://www.linkedin.com/company/credifyone"

  spec.platform = :ios, "12.0"
  spec.requires_arc = true
  spec.source = { git: "https://github.com/credify-pte-ltd/Credify-Crypto-Swift.git", tag: "v#{spec.version}", submodules: true }
  spec.source_files = "CredifyCryptoSwift/**/*.{h,swift}"

end
