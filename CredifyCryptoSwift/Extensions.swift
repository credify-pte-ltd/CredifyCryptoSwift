//
//  Extensions.swift
//  CredifyCryptoSwift
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import Foundation

extension String {
    var data: Data { Data(utf8) }
    var bytes: [UInt8] { .init(utf8) }
    var base64Encoded: Data { data.base64EncodedData() }
    var base64Decoded: Data? { Data(base64Encoded: self) }
}

extension Data {
    var base64Decoded: Data? { Data(base64Encoded: self) }
    var string: String? { String(data: self, encoding: .utf8) }
}
