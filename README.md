# CredifyCryptoSwift

Crypto related functions and helpers for Swift implemented in Swift.

## How to install

### CocoaPods

```
pod 'CredifyCryptoSwift'
```

## Asymmetric Encryption

CredifyCryptoSwift supports RSA encryption with 4096 bit length keys. Its padding scheme uses [OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding).

## Signing

CredifyCryptoSwift utilizes [EdDSA](https://en.wikipedia.org/wiki/EdDSA). This supports Curve25519.

## PKCS #8

In order to simply deal with private keys, this leverages [PKCS #8](https://en.wikipedia.org/wiki/PKCS_8).

## Requirements

- iOS 12+
- Swift 5+

## License

CredifyCryptoSwift is released under the MIT license. See LICENSE for details.
