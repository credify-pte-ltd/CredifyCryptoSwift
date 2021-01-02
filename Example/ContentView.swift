//
//  ContentView.swift
//  Example
//
//  Created by Shuichi Nagao on 2021/01/02.
//

import SwiftUI
import CredifyCryptoSwift

struct ContentView: View {
    var body: some View {
        NavigationView {
            List {
                VStack {
                    NavigationLink(destination: SigningView(siging: .none)) {
                        Text("Signing")
                    }
                }
                VStack {
                    NavigationLink(destination: EncryptionView()) {
                        Text("Encryption")
                    }
                }
            }
            .navigationBarTitle("Credify Crypto")
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
