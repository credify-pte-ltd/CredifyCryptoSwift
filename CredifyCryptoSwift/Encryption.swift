//
//  Encryption.swift
//  CredifyCryptoSwift
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import Foundation
import Crypto

/// Asymmetic Encryption
/// This manages RSA encryption with OAEP. The key size is 4096 bits.
public struct Encryption {
    private let privateKey: CryptoEncryptionKeyProtocol?
    private let publicKey: CryptoEncryptionKeyProtocol?
    
    /// Initializes Encryption with newly generated key pair.
    public init() throws {
        var error: NSError? = nil
        guard let key = CryptoGenerateEncryptionKeyPair(&error) else {
            throw CredifyCryptoSwiftError.rsaKeyGenerationFailed
        }
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.rsaKeyGenerationFailed
        }
        if let pr = key.privateKey, let pu = key.publicKey {
            self.privateKey = pr
            self.publicKey = pu
        } else {
            throw CredifyCryptoSwiftError.rsaKeyGenerationFailed
        }
    }
    
    /// Initializes Encryption with provided key pairs.
    /// This allows at least one key (either private key or public key) to generate a new instance.
    ///
    /// - Parameters:
    ///     - privateKey: Private key restored from a pem file (PKCS#8)
    ///     - publicKey: Public key restored from a pem file (PKCS#8)
    public init(privateKey: String?, publicKey: String?) throws {
        var error: NSError?
        if privateKey == nil && publicKey == nil {
            throw CredifyCryptoSwiftError.rsaEncryptionIncorrectInitialization
        }
        
        var priv: CryptoEncryptionKeyProtocol? = nil
        var pub: CryptoEncryptionKeyProtocol? = nil
        
        // Parse private key
        if let p = privateKey {
            priv = CryptoParseEncryptionPrivateKey(p, &error)
        }
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.rsaPrivateKeyParsingFailed
        }
        
        // Parse public key
        if let p = publicKey {
            pub = CryptoParseEncryptionPublicKey(p, &error)
        }
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.rsaPublicKeyParsingFailed
        }
        
        // If both are empty
        if priv == nil && pub == nil {
            throw CredifyCryptoSwiftError.rsaEncryptionIncorrectInitialization
        }
        
        self.privateKey = priv
        self.publicKey = pub
    }
    
    /// Returns base64 encoded private key string.
    public var base64PrivateKey: String {
        return privateKey?.bytes()?.base64EncodedString() ?? ""
    }
    
    /// Returns base64 encoded public key string.
    public var base64PublicKey: String {
        return publicKey?.bytes()?.base64EncodedString() ?? ""
    }
    
    /// Returns private key in PKCS8 (pem string).
    public var privateKeyPKCS8: String {
        return privateKey?.string() ?? ""
    }
    
    /// Returns public key in PKCS8 (pem string).
    public var publicKeyPKCS8: String {
        return publicKey?.string() ?? ""
    }
    
    /// Encrypts provided plain texts (Data)
    ///
    /// - Parameters:
    ///     - data: Plain texts in Data type.
    public func encrypt(data: Data) throws -> Data {
        guard let pk = self.publicKey else { throw CredifyCryptoSwiftError.rsaPublicKeyMissing }
        do {
            return try pk.encrypt(data)
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.rsaEncryptionInternalError
        }
    }
    
    /// Encrypts provided plain texts (String)
    ///
    /// - Parameters:
    ///     - message: Plain texts in String type.
    public func encrypt(message: String) throws -> Data {
        guard let pk = self.publicKey else { throw CredifyCryptoSwiftError.rsaPublicKeyMissing }
        do {
            return try pk.encrypt(message.data)
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.rsaEncryptionInternalError
        }
    }
    
    /// Decrypts provided cipher texts (Data)
    ///
    /// - Parameters:
    ///     - cipher: Cipher texts in Data type.
    public func decrypt(cipher: Data) throws -> Data {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.rsaPrivateKeyMissing }
        do {
            return try pk.decrypt(cipher)
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.rsaDecryptionInternalError
        }
    }
    
    /// Decrypts provided cipher texts (String)
    ///
    /// - Parameters:
    ///     - cipher: Base64 encoded cipher texts in String type.
    public func decrypt(base64Cipher cipher: String) throws -> Data {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.rsaPrivateKeyMissing }
        do {
            return try pk.decrypt(cipher.base64Decoded)
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.rsaDecryptionInternalError
        }
    }
}
