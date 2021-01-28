//
//  SigningView.swift
//  Example
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import SwiftUI
import CredifyCryptoSwift

struct SigningView: View {
    @State var siging: Signing?
    @State private var message: String = ""
    @State private var sign: String = "(Input something to create Signature)"
    @State private var isEditing = false
    
    var body: some View {
        Button(action: {
            self.siging = try? Signing()
        }) {
            HStack {
                Text("Generate a key")
                    .fontWeight(.regular)
                    .font(.body)
            }
            .padding()
            .foregroundColor(.white)
            .background(Color.green)
            .cornerRadius(8)
        }
        List {
            VStack {
                Text("Private key").bold().padding().foregroundColor(.green)
                Text(siging?.base64UrlPrivateKey ?? "").contextMenu {
                    Button(action: {
                        UIPasteboard.general.string = siging?.base64UrlPrivateKey ?? ""
                    }) {
                        Text("Copy to clipboard")
                        Image(systemName: "doc.on.doc")
                    }
                }
                
            }
            VStack {
                Text("Public key").bold().padding().foregroundColor(.green)
                Text(siging?.base64UrlPublicKey ?? "").contextMenu {
                    Button(action: {
                        UIPasteboard.general.string = siging?.base64UrlPublicKey ?? ""
                    }) {
                        Text("Copy to clipboard")
                        Image(systemName: "doc.on.doc")
                    }
                }
            }
        }
        if siging != nil {
            VStack{
                TextField(
                    "Message to be signed",
                    text: $message
                ) { isEditing in
                    self.isEditing = isEditing
                } onCommit: {
                    let s = try? siging?.sign(message: message)
                    self.sign = s?.base64EncodedString() ?? ""
                }
                .autocapitalization(.none)
                .disableAutocorrection(true)
                .padding()
                .border(Color(UIColor.separator))
                .foregroundColor(isEditing ? .red : .black)
                
                Text(sign).contextMenu {
                    Button(action: {
                        UIPasteboard.general.string = sign
                    }) {
                        Text("Copy to clipboard")
                        Image(systemName: "doc.on.doc")
                    }
                }
            }.padding()
        }
    }
}

struct SigningView_Previews: PreviewProvider {
    @State static var signing: Signing? = try? Signing()
    static var previews: some View {
        SigningView(siging: .none)
    }
}

