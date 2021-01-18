//
//  Errors.swift
//  CredifyCryptoSwift
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import Foundation

/// Credify Crypto Swift Error
public enum CredifyCryptoSwiftError: Error {
    /// Encryption key generation failed
    case rsaKeyGenerationFailed
    
    /// Encryption key initialization has wrong augments
    case rsaEncryptionIncorrectInitialization
    
    /// RSA private key parsing from PKCS8 failed
    case rsaPrivateKeyParsingFailed
    
    /// RSA public key parsing from PKCS8 failed
    case rsaPublicKeyParsingFailed
    
    /// Encryption key initialization has wrong augments, missing private key
    case rsaPrivateKeyMissing
    
    /// Encryption key initialization has wrong augments, missing public key
    case rsaPublicKeyMissing
    
    /// Internal error during encryption
    case rsaEncryptionInternalError
    
    /// Internal error during decryption
    case rsaDecryptionInternalError
    
    /// Curve25519 key generation failed
    case curve25519KeyGenerationFailed
    
    /// Curve25519 key initialization has wrong augments
    case curve25519KeyIncorrectInitialization
    
    /// Curve25519 private key parsing from PKCS8 failed
    case curve25519PrivateKeyParsingFailed
    
    /// Curve25519 public key parsing from PKCS8 failed
    case curve25519PublicKeyParsingFailed
    
    /// Curve25519 key initialization has wrong augments, missing private key
    case curve25519PrivateKeyMissing
    
    /// Curve25519 key initialization has wrong augments, missing public key
    case curve25519PublicKeyMissing
    
    /// Internal error during signing
    case ed25519SigningInternalError
    
    /// Internal error during verification
    case ed25519VerificationInternalError
    
    /// Error during symmetric encryption
    case aesEncryptionError
}

extension CredifyCryptoSwiftError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .rsaKeyGenerationFailed:
            return NSLocalizedString("RSA key generation failed.", comment: "RSA Encryption")
        case .rsaEncryptionIncorrectInitialization:
            return NSLocalizedString("Incorrect initialization of Encryption", comment: "RSA Encryption")
        case .rsaPrivateKeyParsingFailed:
            return NSLocalizedString("Could not parse the provided RSA private key.", comment: "RSA Encryption")
        case .rsaPublicKeyParsingFailed:
            return NSLocalizedString("Could not parse the provided RSA public key.", comment: "RSA Encryption")
        case .rsaPrivateKeyMissing:
            return NSLocalizedString("Please provide a private key in `init`.", comment: "RSA Encryption")
        case .rsaPublicKeyMissing:
            return NSLocalizedString("Please provide a public key in `init`.", comment: "RSA Encryption")
        case .rsaEncryptionInternalError:
            return NSLocalizedString("Internal error during encryption.", comment: "RSA Encryption")
        case .rsaDecryptionInternalError:
            return NSLocalizedString("Internal error during decryption.", comment: "RSA Encryption")
        case .curve25519KeyGenerationFailed:
            return NSLocalizedString("Curve25519 key generation failed.", comment: "Ed25519 Signing")
        case .curve25519KeyIncorrectInitialization:
            return NSLocalizedString("Incorrect initialization of Curve25519 key.", comment: "Ed25519 Signing")
        case .curve25519PrivateKeyParsingFailed:
            return NSLocalizedString("Could not parse the provided Curve25519 private key.", comment: "Ed25519 Signing")
        case .curve25519PublicKeyParsingFailed:
            return NSLocalizedString("Could not parse the provided Curve25519 public key.", comment: "Ed25519 Signing")
        case .curve25519PrivateKeyMissing:
            return NSLocalizedString("Please provide a private key in `init`.", comment: "Ed25519 Signing")
        case .curve25519PublicKeyMissing:
            return NSLocalizedString("Please provide a public key in `init`.", comment: "Ed25519 Signing")
        case .ed25519SigningInternalError:
            return NSLocalizedString("Internal error during signing.", comment: "Ed25519 Signing")
        case .ed25519VerificationInternalError:
            return NSLocalizedString("Internal error during verification.", comment: "Ed25519 Signing")
        case .aesEncryptionError:
            return NSLocalizedString("Symmetric encryption error", comment: "Password encryption")
        }
    }
}
