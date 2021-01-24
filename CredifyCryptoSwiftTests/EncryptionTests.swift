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
        XCTAssertNotEqual(subject.base64UrlPrivateKey, "")
        XCTAssertNotEqual(subject.base64UrlPublicKey, "")
        XCTAssertNotEqual(subject.privateKeyPKCS8, "")
        XCTAssertNotEqual(subject.publicKeyPKCS8, "")
    }
    
    func testKey_Generation_from_pem() throws {
        setup()
        
        XCTAssertNotEqual(subject.base64UrlPrivateKey, "")
        XCTAssertNotEqual(subject.base64UrlPublicKey, "")
        XCTAssertNotEqual(subject.privateKeyPKCS8, "")
        XCTAssertNotEqual(subject.publicKeyPKCS8, "")
    }
    
    func testEncrypt() throws {
        setup()
        
        
        let enc = try! subject.encrypt(data: str.data)
        XCTAssertNotEqual(enc.base64EncodedString(), "")
        let dec = try! subject.decrypt(cipher: enc)
        XCTAssertEqual(dec.string, str)
    }
    
    func testEncryptBase64Url() throws {
        setup()
        
        
        let enc = try! subject.encryptBase64Url(message: str)
        XCTAssertNotEqual(enc, "")
        let dec = try! subject.decrypt(base64UrlCipher: enc)
        XCTAssertEqual(dec, str)
    }

    func testDecrypt_presigned_value() throws {
        setup()
        
        let encrypted = "XGI1icHgMVuTvYLMEwXpcE4XcvTcfSW4fTr+slI5Q1XgX9cjGe/r84d31StdnGVYAQzPjuXYZ6ifKuak3fof7ggBi+OVnFJXUQAC0UCCCMI+Yyon1peJ2TrnDoKO5vXjCsyb9k0eU7N0k3/zHb0hjgKvoCGCaV/MIxDKsnwDwRGakFTQp2B31ajEuM07mXbO9srYGJhyxw8qXD3d/KiyO26W2NBzvp8mSDUf1KSwT3TD24nlrl5VTSR1bQSWEIT56JENl9lB1LWOTXtxx6ZQ6bSo5HSJFVX0wJW6db6xLtiizkVY0DaOwOay8q4KImcBuVX6EvYnjAWwK0EitsehlbBMJOmfbmC4U0+yKwq5pwSxB0HsrAunlWLjq2/5eV0oMBGaFD3BIwISaP3kLEfWxhjIBl2XNbT94fLuiP3ZLFnfJXqMEbbBRrSleuvbzeBr5/KLYrfrMTLIHMn7U7usu65zYXKkJKp8MqLMv5wGlvmDce5Yxv+mrCKciJSDHfJ1MQoEUKAGsQT2l3vkyBcAfuJ1HNXoyEGAupsQc4PD4KBOt3cdV4m6owCXO7IfxHnS3M7JaVahYsHlix+xOUgJLtoOPNy3HyN3OVaFXar0AZgr/nWs0686RPHx3sqyI8/plMpP/Rnm+Z+KL9CyZqWh0JEm7wHYCfEqkHxv5FdyWaw="
        
        let dec = try! subject.decrypt(cipher: encrypted.base64Decoded!)
        XCTAssertEqual(dec.string, str)
    }
    
    func testDecryptBase64Url_presigned_value() throws {
        setup()
        let encrypted = "YDLM-8gTpqBgQzvYRqasgv-_u5Jthawk0cTJJSlRJIACJCYsB6u7LJpAiE5vHxa8B1yQ4Vg5w271X2seMwXEJn4xpbM44lUqAUpItdmGcsktVaEB2lpf7_GqMv6XEhOjc1JoanGm3tp6vySmcWv8g-XWZVmusiJKfvnppJKSoaxpT2C3aZ1dzLlMZdVssen6Cz1D3agspzi_hG8v-t7tbeV-g7jKPmXAKJswwahAkJgXs7pJzQ-GGSXksbKGr11Z0XkM-mivaX0w1B6GQcQIYYUi_0IoPEUzTc1Mpv6LErtJryXnlCUKAo5u1a8WpLjEPlrhCBJiXXX63a7dGmE37pjhs5Bw74MJK6Y8chFHpAUemJnZbfs8gY2RGh-Nkt6jeNSpJ2IrDSAPfvhFHbSxrEhNuSVy0KCdi_xqGGD40bmI8QIgTfmusFHMW3iCKm1yAD-55R745vNvAto69FIA--Ek6Gle8Z3eKSPKBgfZE3NbKpATExMU1LU1mhCffOdG6hKUvTrsEBN_ob3UOn6g9JcaiPH9ezAe1bB48U3-TsyJ-ypNKWOxV46B2VsKnQgL-ire8T4ZCck-32usUWAlhFPUkXxTYYNSej2CXZY8ukSpdED5vy-D_g-xiWn9MI51oL2XUONc8KvOd1KlUf87OYwdS0EDFlOWu1DlsUTaYnk"
        
        let dec = try! subject.decrypt(base64UrlCipher: encrypted)
        XCTAssertEqual(dec, str)
    }

    private func setup() {
        let bundle = Bundle(for: type(of: self))
        let privFilepath = bundle.path(forResource: privateKeyFile, ofType: "pem")!
        let pubFilepath = bundle.path(forResource: publicKeyFile, ofType: "pem")!
        let privateKeyPEM = try! String(contentsOfFile: privFilepath)
        let publicKeyPEM = try! String(contentsOfFile: pubFilepath)
        
        subject = try! Encryption(privateKey: privateKeyPEM, publicKey: publicKeyPEM, password: nil)
    }
}
