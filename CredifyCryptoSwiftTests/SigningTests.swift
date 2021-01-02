//
//  SigningTests.swift
//  CredifyCryptoSwiftTests
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import XCTest
@testable import CredifyCryptoSwift

class SigningTests: XCTestCase {

    var subject: Signing!
    let privateKeyFile = "testPrivateKeySign"
    let publicKeyFile = "testPublicKeySign"
    let str = "This is a test message!"

    override func setUpWithError() throws {
        subject = try! Signing()
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
        
        subject = try! Signing(privateKey: privateKeyPEM, publicKey: publicKeyPEM)
        
        XCTAssertEqual(subject.base64PrivateKey, "MC4CAQAwBQYDK2VwBCIEIPqO4b4UtXSaWGp5u38rCXYu4/LdbaSk7lD46LtRUu44")
        XCTAssertEqual(subject.base64PublicKey, "MCowBQYDK2VwAyEAfMZuEAjsoPr5GopucNfoY8ecwfsZ3XSXsY3zdG6ujCM=")
        XCTAssertNotEqual(subject.privateKeyPKCS8, "")
        XCTAssertNotEqual(subject.publicKeyPKCS8, "")
    }
    
    func testSign() throws {
        let bundle = Bundle(for: type(of: self))
        let privFilepath = bundle.path(forResource: privateKeyFile, ofType: "pem")!
        let pubFilepath = bundle.path(forResource: publicKeyFile, ofType: "pem")!
        let privateKeyPEM = try! String(contentsOfFile: privFilepath)
        let publicKeyPEM = try! String(contentsOfFile: pubFilepath)
        
        subject = try! Signing(privateKey: privateKeyPEM, publicKey: publicKeyPEM)
        
        let sign = try! subject.sign(data: str.data)
        XCTAssertEqual(sign.base64EncodedString(), "oJ6yDFkgsQk8wMqLQm2vtBVKxJ69fH2oU5SYIrCaTy5RjHdpIFBT/UV8I8PbJj/Gv7ll2bc2FFGepURUC23SBg==")
        XCTAssertEqual(try! subject.verify(signature: sign, message: str), true)
    }

}
