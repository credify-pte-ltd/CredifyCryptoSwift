//
//  Signing.swift
//  CredifyCryptoSwift
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import Foundation
import Crypto

public struct Signing {
    private let privateKey: CryptoSigningKeyProtocol?
    private let publicKey: CryptoVerificationKeyProtocol?
    
    /// Initializes Signing with newly generated key pair.
    public init() throws {
        var error: NSError?
        let key = CryptoGenerateSigningKeyPair(&error)
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.curve25519KeyGenerationFailed
        }
        if let k = key {
            self.privateKey = k.signingKey
            self.publicKey = k.verificationKey
        } else {
            throw CredifyCryptoSwiftError.curve25519KeyGenerationFailed
        }
    }
    
    /// Initializes signing key with provided key pairs.
    /// This allows at least one key (either private key or public key) to generate a new instance.
    ///
    /// - Parameters:
    ///     - privateKey: Private key restored from a pem file (PKCS#8)
    ///     - publicKey: Public key restored from a pem file (PKCS#8)
    ///     - password: Password in case the private key is encrypted
    public init(privateKey: String?, publicKey: String?, password: String?) throws {
        var error: NSError?
        if privateKey == nil && publicKey == nil {
            throw CredifyCryptoSwiftError.curve25519KeyIncorrectInitialization
        }
        
        var priv: CryptoSigningKeyProtocol? = nil
        var pub: CryptoVerificationKeyProtocol? = nil

        // Parse private key with a password
        if let p = privateKey, let pw = password {
            priv = CryptoDecryptSigningKey(p, pw, &error)
        }
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.curve25519PrivateKeyParsingFailed
        }
        
        // Parse private key without a password
        if let p = privateKey, password == nil {
            priv = CryptoParseSigningKey(p, &error)
        }
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.curve25519PrivateKeyParsingFailed
        }
        
        // Parse public key
        if let p = publicKey {
            pub = CryptoParseVerificationKey(p, &error)
        }
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.curve25519PublicKeyParsingFailed
        }
        
        // If both are empty
        if priv == nil && pub == nil {
            throw CredifyCryptoSwiftError.curve25519KeyIncorrectInitialization
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
    
    
    /// Generates a signature of provided data
    ///
    /// - Parameters:
    ///     - data: Message to be signed in Data type.
    public func sign(data: Data) throws -> Data {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.curve25519PrivateKeyMissing }
        do {
            return try pk.sign(data)
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.ed25519SigningInternalError
        }
    }
    
    /// Generates a signature of provided message
    ///
    /// - Parameters:
    ///     - message: Message to be signed in String type.
    public func sign(message: String) throws -> Data {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.curve25519PrivateKeyMissing }
        do {
            return try pk.sign(message.data)
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.ed25519SigningInternalError
        }
    }
    
    /// Verifies a signature with public key
    ///
    /// - Parameters:
    ///     - signature: Sinature Data.
    ///     - message: Message to be signed in String type.
    func verify(signature: Data, message: String) throws -> Bool {
        guard let pk = self.publicKey else { throw CredifyCryptoSwiftError.curve25519PublicKeyMissing }
        do {
            var isValid: ObjCBool = false
            try pk.verify(signature, message: message.data, valid: &isValid)
            return isValid.boolValue
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.ed25519VerificationInternalError
        }
    }
    
    /// Verifies a signature with public key
    ///
    /// - Parameters:
    ///     - base64Signature: Base64 encoded sinature.
    ///     - message: Message to be signed in String type.
    func verify(base64Signature: String, message: String) throws -> Bool {
        guard let pk = self.publicKey else { throw CredifyCryptoSwiftError.curve25519PublicKeyMissing }
        do {
            var isValid: ObjCBool = false
            try pk.verify(base64Signature.base64Decoded, message: message.data, valid: &isValid)
            return isValid.boolValue
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.ed25519VerificationInternalError
        }
    }
    
    /// Exports an encrypted private key
    ///
    /// - Parameters:
    ///     - password: password to encrypt the private key
    func exportPrivateKey(password: String) throws -> String {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.curve25519PrivateKeyMissing }

        var error: NSError?
        let key = pk.export(password, error: &error)
        
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.aesEncryptionError
        }
        return key
    }
}
