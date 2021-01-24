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
    ///     - password: Password in case the private key is encrypted
    public init(privateKey: String?, publicKey: String?, password: String?) throws {
        var error: NSError?
        if privateKey == nil && publicKey == nil {
            throw CredifyCryptoSwiftError.rsaEncryptionIncorrectInitialization
        }
        
        var priv: CryptoEncryptionKeyProtocol? = nil
        var pub: CryptoEncryptionKeyProtocol? = nil
        
        // Parse private key with a password
        if let p = privateKey, let pw = password {
            priv = CryptoDecryptEncryptionPrivateKey(p, pw, &error)
        }
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.rsaPrivateKeyParsingFailed
        }
        
        // Parse private key without a password
        if let p = privateKey, password == nil {
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
    
    /// Returns base64 URL encoded private key string.
    public var base64UrlPrivateKey: String {
        return privateKey?.stringParam() ?? ""
    }
    
    /// Returns base64 URL encoded public key string.
    public var base64UrlPublicKey: String {
        return publicKey?.stringParam() ?? ""
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
    
    /// Encrypts provided plain texts (String) into base64 URL
    ///
    /// - Parameters:
    ///     - message: Plain texts in String type.
    public func encryptBase64Url(message: String) throws -> String {
        guard let pk = self.publicKey else { throw CredifyCryptoSwiftError.rsaPublicKeyMissing }
        var error: NSError? = nil
        let cipher = pk.encrypt(asBase64: message.data, error: &error)
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.rsaEncryptionInternalError
        }
        return cipher
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
    ///     - cipher: Base64 URL encoded cipher texts in String type.
    public func decrypt(base64UrlCipher cipher: String) throws -> String {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.rsaPrivateKeyMissing }
        do {
            return try pk.decryptBase64(cipher).string ?? ""
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.rsaDecryptionInternalError
        }
    }
    
    /// Exports an encrypted private key
    ///
    /// - Parameters:
    ///     - password: password to encrypt the private key
    public func exportPrivateKey(password: String) throws -> String {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.rsaPrivateKeyMissing }

        var error: NSError?
        let key = pk.export(password, error: &error)
        
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.aesEncryptionError
        }
        return key
    }
}
