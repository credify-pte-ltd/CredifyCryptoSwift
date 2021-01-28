//
//  Signing.swift
//  CredifyCryptoSwift
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import Foundation
import Crypto

public enum EncodeType {
    case none, base64, base64URL
}

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
    
    /**
     Generates a base64 URL encoded signature of provided message
     - Parameters:
        - message: Message to be signed in String type.
        - option: encode type of message
            * none -> message is not encode
            * base64 -> message is encode by base64
            * base64URL -> message is encode by base64URL
     */
    public func signBase64Url(message: String, option: EncodeType = .none) throws -> String {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.curve25519PrivateKeyMissing }
        
        var error: NSError?
        var decodeMessage = message
        switch option {
        case .base64:
            decodeMessage = message.base64Decoded?.string ?? ""
        case .base64URL:
            do {
                decodeMessage = try Signing.decodeBase64URL(message: decodeMessage)
            }catch {
                throw CredifyCryptoSwiftError.ed25519SigningInternalError
            }
        case .none:
            break
        }
        let sign = pk.sign(asBase64: decodeMessage.data, error: &error)
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.ed25519SigningInternalError
        }
        return sign
        
    }
    
    /// Verifies a signature with public key
    ///
    /// - Parameters:
    ///     - signature: Sinature Data.
    ///     - message: Message to be signed in String type.
    public func verify(signature: Data, message: String) throws -> Bool {
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
    ///     - base64UrlSignature: Base64 encoded sinature.
    ///     - message: Message to be signed in String type.
    public func verify(base64UrlSignature: String, message: String) throws -> Bool {
        guard let pk = self.publicKey else { throw CredifyCryptoSwiftError.curve25519PublicKeyMissing }
        do {
            var isValid: ObjCBool = false
            try pk.verifyBase64(base64UrlSignature, message: message.data, valid: &isValid)
            return isValid.boolValue
        } catch (let error) {
            print(error)
            throw CredifyCryptoSwiftError.ed25519VerificationInternalError
        }
    }
    
    /// Returns a token to generate an access token.
    public func generateLoginToken() -> String {
        return CryptoLoginToken(privateKey, publicKey)
    }
    
    /// Returns if a passed token is valid or not.
    public func verifyLoginToken(_ token: String) -> Bool {
        var error: NSError? = nil
        guard let claims = CryptoParseLoginToken(token, &error) else {
            return false
        }
        print(claims)
        return true
    }
    
    /// Exports an encrypted private key
    ///
    /// - Parameters:
    ///     - password: password to encrypt the private key
    public func exportPrivateKey(password: String) throws -> String {
        guard let pk = self.privateKey else { throw CredifyCryptoSwiftError.curve25519PrivateKeyMissing }

        var error: NSError?
        let key = pk.export(password, error: &error)
        
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.aesEncryptionError
        }
        return key
    }
    
    static func decodeBase64URL(message: String) throws -> String {
        var error: NSError?
        let decodeData = CryptoDecodeBase64(message, &error)
        
        if let e = error {
            print(e)
            throw CredifyCryptoSwiftError.ed25519SigningInternalError
        }
        
        if let result = decodeData?.string {
            return result
        }else {
            throw CredifyCryptoSwiftError.ed25519SigningInternalError
        }
    }
    
    static func encodeBase64URL(message: String) -> String {
        let encodeMessage = CryptoEncodeBase64(message.data)
        return encodeMessage
    }
}
