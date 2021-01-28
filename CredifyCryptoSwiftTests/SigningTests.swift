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
        XCTAssertNotEqual(subject.base64UrlPrivateKey, "")
        XCTAssertNotEqual(subject.base64UrlPublicKey, "")
        XCTAssertNotEqual(subject.privateKeyPKCS8, "")
        XCTAssertNotEqual(subject.publicKeyPKCS8, "")
    }
    
    func testKey_Generation_from_pem() throws {
        setup()
        
        XCTAssertEqual(subject.base64UrlPrivateKey, "MC4CAQAwBQYDK2VwBCIEIPqO4b4UtXSaWGp5u38rCXYu4_LdbaSk7lD46LtRUu44")
        XCTAssertEqual(subject.base64UrlPublicKey, "MCowBQYDK2VwAyEAfMZuEAjsoPr5GopucNfoY8ecwfsZ3XSXsY3zdG6ujCM")
        XCTAssertNotEqual(subject.privateKeyPKCS8, "")
        XCTAssertNotEqual(subject.publicKeyPKCS8, "")
    }
    
    func testSign() throws {
        setup()
        
        let sign = try! subject.sign(data: str.data)
        XCTAssertEqual(sign.base64EncodedString(), "oJ6yDFkgsQk8wMqLQm2vtBVKxJ69fH2oU5SYIrCaTy5RjHdpIFBT/UV8I8PbJj/Gv7ll2bc2FFGepURUC23SBg==")
        XCTAssertEqual(try! subject.verify(signature: sign, message: str), true)
        
        let signBase64UrlTestOne = try! subject.signBase64Url(message: str)
        XCTAssertEqual(signBase64UrlTestOne, "oJ6yDFkgsQk8wMqLQm2vtBVKxJ69fH2oU5SYIrCaTy5RjHdpIFBT_UV8I8PbJj_Gv7ll2bc2FFGepURUC23SBg")
        XCTAssertTrue(try! subject.verify(base64UrlSignature: signBase64UrlTestOne, message: str))
        
        let encodeBase64URL = Signing.encodeBase64URL(message: str)
        XCTAssertEqual(encodeBase64URL, "VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSE")

        let signBase64UrlTestTwo = try! subject.signBase64Url(message: encodeBase64URL, option: .base64URL)
        XCTAssertEqual(signBase64UrlTestTwo, "oJ6yDFkgsQk8wMqLQm2vtBVKxJ69fH2oU5SYIrCaTy5RjHdpIFBT_UV8I8PbJj_Gv7ll2bc2FFGepURUC23SBg")
        XCTAssertTrue(try! subject.verify(base64UrlSignature: signBase64UrlTestTwo, message: str))
        
        let encodeBase64 = str.base64Encoded.string
        XCTAssertEqual(encodeBase64, "VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSE=")
        
        let signBase64UrlTestThree = try! subject.signBase64Url(message: encodeBase64!, option: .base64)
        XCTAssertEqual(signBase64UrlTestThree, "oJ6yDFkgsQk8wMqLQm2vtBVKxJ69fH2oU5SYIrCaTy5RjHdpIFBT_UV8I8PbJj_Gv7ll2bc2FFGepURUC23SBg")
        XCTAssertTrue(try! subject.verify(base64UrlSignature: signBase64UrlTestThree, message: str))
    }
    
    func testEncode_and_decode_base64URL() {
        setUp()
        let encode = Signing.encodeBase64URL(message: str)
        XCTAssertEqual(encode, "VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSE")
        XCTAssertEqual(try! Signing.decodeBase64URL(message: encode), str)
    }

    func testGenerateLoginToken() {
        setup()
        XCTAssertNotEqual(subject.generateLoginToken(), "")
    }
    
    private func setup() {
        let bundle = Bundle(for: type(of: self))
        let privFilepath = bundle.path(forResource: privateKeyFile, ofType: "pem")!
        let pubFilepath = bundle.path(forResource: publicKeyFile, ofType: "pem")!
        let privateKeyPEM = try! String(contentsOfFile: privFilepath)
        let publicKeyPEM = try! String(contentsOfFile: pubFilepath)
        
        subject = try! Signing(privateKey: privateKeyPEM, publicKey: publicKeyPEM, password: nil)
    }
}
