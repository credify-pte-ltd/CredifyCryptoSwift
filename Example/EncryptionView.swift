//
//  EncryptionView.swift
//  Example
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import SwiftUI
import CredifyCryptoSwift

struct EncryptionView: View {
    @State var encryption: Encryption?
    @State private var message: String = ""
    @State private var enc: String = "(Input something to create encrypted message)"
    @State private var isEditing = false
    
    var body: some View {
        Button(action: {
            self.encryption = try? Encryption()
        }) {
            HStack {
                Text("Generate a key")
                    .fontWeight(.regular)
                    .font(.body)
            }
            .padding()
            .foregroundColor(.white)
            .background(Color.blue)
            .cornerRadius(8)
        }
        List {
            VStack {
                Text("Private key").bold().padding().foregroundColor(.blue)
                Text(encryption?.base64PrivateKey ?? "").contextMenu {
                    Button(action: {
                        UIPasteboard.general.string = encryption?.base64PrivateKey ?? ""
                    }) {
                        Text("Copy to clipboard")
                        Image(systemName: "doc.on.doc")
                    }
                }
                
            }
            VStack {
                Text("Public key").bold().padding().foregroundColor(.blue)
                Text(encryption?.base64PublicKey ?? "").contextMenu {
                    Button(action: {
                        UIPasteboard.general.string = encryption?.base64PublicKey ?? ""
                    }) {
                        Text("Copy to clipboard")
                        Image(systemName: "doc.on.doc")
                    }
                }
            }
        }
        if encryption != nil {
            VStack{
                TextField(
                    "Message to be encrypted",
                    text: $message
                ) { isEditing in
                    self.isEditing = isEditing
                } onCommit: {
                    let e = try? encryption?.encrypt(message: message)
                    self.enc = e?.base64EncodedString() ?? ""
                }
                .autocapitalization(.none)
                .disableAutocorrection(true)
                .padding()
                .border(Color(UIColor.separator))
                .foregroundColor(isEditing ? .red : .black)
                
                Text(enc).contextMenu {
                    Button(action: {
                        UIPasteboard.general.string = enc
                    }) {
                        Text("Copy to clipboard")
                        Image(systemName: "doc.on.doc")
                    }
                }
            }.padding()
        }
    }
}

struct EncryptionView_Previews: PreviewProvider {
    static var previews: some View {
        EncryptionView()
    }
}
