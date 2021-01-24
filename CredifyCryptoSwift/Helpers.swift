//
//  Helpers.swift
//  CredifyCryptoSwift
//
//  Created by Shuichi Nagao on 2021/01/24.
//

import Foundation
import Crypto

public struct CryptoHelpers {
    /**
     Returns sha256 value in Base64 URL encoded format.
     - Parameters
        - message: String
     */
    public static func sha256(message: String) -> String {
        return CryptoEncodeBase64(CryptoHash(message.data))
    }
    
    /**
     Generates a random salt for hashing.
     */
    public static func generateSalt() -> String {
        var error: NSError? = nil
        let salt = CryptoGenerateSaltAsBase64(&error)
        if let e = error {
            print(e)
            return ""
        }
        return salt
    }
}
