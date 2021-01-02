//
//  EncryptionTests.swift
//  CredifyCryptoSwiftTests
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import XCTest
@testable import CredifyCryptoSwift

class EncryptionTests: XCTestCase {

    var subject: Encryption!
    let privateKeyFile = "testPrivateKey"
    let publicKeyFile = "testPublicKey"
    let str = "This is a test message!"
    
    override func setUpWithError() throws {
        subject = try! Encryption()
    }

    override func tearDownWithError() throws {
        subject = nil
    }

    func testKey_Generation() throws {
        XCTAssertNotEqual(subject.base64PrivateKey, "")
        XCTAssertNotEqual(subject.base64PublicKey, "")
        XCTAssertNotEqual(subject.privateKeyPKCS8, "")
        XCTAssertNotEqual(subject.publicKeyPKCS8, "")
    }
    
    func testKey_Generation_from_pem() throws {
        let bundle = Bundle(for: type(of: self))
        let privFilepath = bundle.path(forResource: privateKeyFile, ofType: "pem")!
        let pubFilepath = bundle.path(forResource: publicKeyFile, ofType: "pem")!
        let privateKeyPEM = try! String(contentsOfFile: privFilepath)
        let publicKeyPEM = try! String(contentsOfFile: pubFilepath)
        
        subject = try! Encryption(privateKey: privateKeyPEM, publicKey: publicKeyPEM)
        
        XCTAssertNotEqual(subject.base64PrivateKey, "")
        XCTAssertNotEqual(subject.base64PublicKey, "")
        XCTAssertNotEqual(subject.privateKeyPKCS8, "")
        XCTAssertNotEqual(subject.publicKeyPKCS8, "")
    }
    
    func testSign() throws {
        let bundle = Bundle(for: type(of: self))
        let privFilepath = bundle.path(forResource: privateKeyFile, ofType: "pem")!
        let pubFilepath = bundle.path(forResource: publicKeyFile, ofType: "pem")!
        let privateKeyPEM = try! String(contentsOfFile: privFilepath)
        let publicKeyPEM = try! String(contentsOfFile: pubFilepath)
        
        subject = try! Encryption(privateKey: privateKeyPEM, publicKey: publicKeyPEM)
        
        
        let enc = try! subject.encrypt(data: str.data)
        XCTAssertNotEqual(enc.base64EncodedString(), "")
        let dec = try! subject.decrypt(cipher: enc)
        XCTAssertEqual(dec.string, str)
    }

    func testSign_presigned_value() throws {
        let bundle = Bundle(for: type(of: self))
        let privFilepath = bundle.path(forResource: privateKeyFile, ofType: "pem")!
        let pubFilepath = bundle.path(forResource: publicKeyFile, ofType: "pem")!
        let privateKeyPEM = try! String(contentsOfFile: privFilepath)
        let publicKeyPEM = try! String(contentsOfFile: pubFilepath)
        
        subject = try! Encryption(privateKey: privateKeyPEM, publicKey: publicKeyPEM)
        
        let encrypted = "XGI1icHgMVuTvYLMEwXpcE4XcvTcfSW4fTr+slI5Q1XgX9cjGe/r84d31StdnGVYAQzPjuXYZ6ifKuak3fof7ggBi+OVnFJXUQAC0UCCCMI+Yyon1peJ2TrnDoKO5vXjCsyb9k0eU7N0k3/zHb0hjgKvoCGCaV/MIxDKsnwDwRGakFTQp2B31ajEuM07mXbO9srYGJhyxw8qXD3d/KiyO26W2NBzvp8mSDUf1KSwT3TD24nlrl5VTSR1bQSWEIT56JENl9lB1LWOTXtxx6ZQ6bSo5HSJFVX0wJW6db6xLtiizkVY0DaOwOay8q4KImcBuVX6EvYnjAWwK0EitsehlbBMJOmfbmC4U0+yKwq5pwSxB0HsrAunlWLjq2/5eV0oMBGaFD3BIwISaP3kLEfWxhjIBl2XNbT94fLuiP3ZLFnfJXqMEbbBRrSleuvbzeBr5/KLYrfrMTLIHMn7U7usu65zYXKkJKp8MqLMv5wGlvmDce5Yxv+mrCKciJSDHfJ1MQoEUKAGsQT2l3vkyBcAfuJ1HNXoyEGAupsQc4PD4KBOt3cdV4m6owCXO7IfxHnS3M7JaVahYsHlix+xOUgJLtoOPNy3HyN3OVaFXar0AZgr/nWs0686RPHx3sqyI8/plMpP/Rnm+Z+KL9CyZqWh0JEm7wHYCfEqkHxv5FdyWaw="
        
        let dec = try! subject.decrypt(cipher: encrypted.base64Decoded!)
        XCTAssertEqual(dec.string, str)
    }

}
