// Objective-C API for talking to gitlab.com/credify.one/sdks/crypto Go package.
//   gobind -lang=objc gitlab.com/credify.one/sdks/crypto
//
// File is generated by gobind. Do not edit.

#ifndef __Crypto_H__
#define __Crypto_H__

@import Foundation;
#include "ref.h"
#include "Universe.objc.h"


@class CryptoApprovalTokenClaims;
@class CryptoEncryptionKeyPair;
@class CryptoIdentityTokenClaims;
@class CryptoLoginClaims;
@class CryptoMaskedText;
@class CryptoRequestTokenClaims;
@class CryptoSigningKeyPair;
@protocol CryptoEncryptionKey;
@class CryptoEncryptionKey;
@protocol CryptoSerializable;
@class CryptoSerializable;
@protocol CryptoSigningKey;
@class CryptoSigningKey;
@protocol CryptoVerificationKey;
@class CryptoVerificationKey;

@protocol CryptoEncryptionKey <NSObject>
- (NSData* _Nullable)bytes;
- (NSData* _Nullable)decrypt:(NSData* _Nullable)cipher error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)decryptBase64:(NSString* _Nullable)cipher error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)encrypt:(NSData* _Nullable)plain error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)encryptAsBase64:(NSData* _Nullable)plain error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)export:(NSString* _Nullable)password error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
@end

@protocol CryptoSerializable <NSObject>
- (NSData* _Nullable)bytes;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
@end

@protocol CryptoSigningKey <NSObject>
- (NSData* _Nullable)bytes;
- (NSString* _Nonnull)export:(NSString* _Nullable)password error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)sign:(NSData* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)signAsBase64:(NSData* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
- (id<CryptoVerificationKey> _Nullable)verificationKey:(NSError* _Nullable* _Nullable)error;
@end

@protocol CryptoVerificationKey <NSObject>
- (NSData* _Nullable)bytes;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
- (BOOL)verify:(NSData* _Nullable)signature message:(NSData* _Nullable)message valid:(BOOL* _Nullable)valid error:(NSError* _Nullable* _Nullable)error;
- (BOOL)verifyBase64:(NSString* _Nullable)signature message:(NSData* _Nullable)message valid:(BOOL* _Nullable)valid error:(NSError* _Nullable* _Nullable)error;
@end

@interface CryptoApprovalTokenClaims : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field ApprovalTokenClaims.StandardClaims with unsupported type: github.com/dgrijalva/jwt-go.StandardClaims

@property (nonatomic) NSString* _Nonnull clientId;
@property (nonatomic) NSString* _Nonnull scopes;
@property (nonatomic) NSString* _Nonnull offerCode;
- (BOOL)valid:(NSError* _Nullable* _Nullable)error;
- (BOOL)verifyAudience:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyExpiresAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuedAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuer:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyNotBefore:(int64_t)cmp req:(BOOL)req;
@end

@interface CryptoEncryptionKeyPair : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) id<CryptoEncryptionKey> _Nullable privateKey;
@property (nonatomic) id<CryptoEncryptionKey> _Nullable publicKey;
@end

@interface CryptoIdentityTokenClaims : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field IdentityTokenClaims.StandardClaims with unsupported type: github.com/dgrijalva/jwt-go.StandardClaims

@property (nonatomic) NSString* _Nonnull identitySource;
@property (nonatomic) NSString* _Nonnull identityHash;
- (BOOL)valid:(NSError* _Nullable* _Nullable)error;
- (BOOL)verifyAudience:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyExpiresAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuedAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuer:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyNotBefore:(int64_t)cmp req:(BOOL)req;
@end

@interface CryptoLoginClaims : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field LoginClaims.StandardClaims with unsupported type: github.com/dgrijalva/jwt-go.StandardClaims

@property (nonatomic) NSString* _Nonnull signingKey;
- (BOOL)valid:(NSError* _Nullable* _Nullable)error;
- (BOOL)verifyAudience:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyExpiresAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuedAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuer:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyNotBefore:(int64_t)cmp req:(BOOL)req;
@end

@interface CryptoMaskedText : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field MaskedText.Hash with unsupported type: gitlab.com/credify.one/sdks/crypto.HashedText

// skipped field MaskedText.Cipher with unsupported type: gitlab.com/credify.one/sdks/crypto.CipherText

@end

@interface CryptoRequestTokenClaims : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field RequestTokenClaims.StandardClaims with unsupported type: github.com/dgrijalva/jwt-go.StandardClaims

@property (nonatomic) NSString* _Nonnull encryptionPublicKey;
@property (nonatomic) NSString* _Nonnull scopes;
@property (nonatomic) NSString* _Nonnull offerCode;
- (BOOL)valid:(NSError* _Nullable* _Nullable)error;
- (BOOL)verifyAudience:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyExpiresAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuedAt:(int64_t)cmp req:(BOOL)req;
- (BOOL)verifyIssuer:(NSString* _Nullable)cmp req:(BOOL)req;
- (BOOL)verifyNotBefore:(int64_t)cmp req:(BOOL)req;
@end

@interface CryptoSigningKeyPair : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) id<CryptoSigningKey> _Nullable signingKey;
@property (nonatomic) id<CryptoVerificationKey> _Nullable verificationKey;
@end

FOUNDATION_EXPORT NSString* _Nonnull const CryptoEd25519SigningAlgorithm;
FOUNDATION_EXPORT NSString* _Nonnull const CryptoEncryptedPrivateKeyBlockType;
FOUNDATION_EXPORT NSString* _Nonnull const CryptoPrivateKeyBlockType;
FOUNDATION_EXPORT NSString* _Nonnull const CryptoPublicKeyBlockType;
FOUNDATION_EXPORT const int64_t CryptoRsaKeyLength;

// skipped function CipherTextValue with unsupported parameter or return types


FOUNDATION_EXPORT NSData* _Nullable CryptoDecodeBase64(NSString* _Nullable payload, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoEncryptionKey> _Nullable CryptoDecryptEncryptionPrivateKey(NSString* _Nullable encryptedPem, NSString* _Nullable password, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoSigningKey> _Nullable CryptoDecryptSigningKey(NSString* _Nullable encryptedPem, NSString* _Nullable password, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT NSString* _Nonnull CryptoEncodeBase64(NSData* _Nullable payload);

FOUNDATION_EXPORT id<CryptoEncryptionKey> _Nullable CryptoEncryptionPrivateKeyFromPem(NSString* _Nullable pem);

FOUNDATION_EXPORT id<CryptoEncryptionKey> _Nullable CryptoEncryptionPublicKeyFromPem(NSString* _Nullable pem);

FOUNDATION_EXPORT CryptoEncryptionKeyPair* _Nullable CryptoGenerateEncryptionKeyPair(NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT NSData* _Nullable CryptoGenerateSalt(NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT NSString* _Nonnull CryptoGenerateSaltAsBase64(NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT CryptoSigningKeyPair* _Nullable CryptoGenerateSigningKeyPair(NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT NSData* _Nullable CryptoHash(NSData* _Nullable message);

// skipped function HashedTextValue with unsupported parameter or return types


FOUNDATION_EXPORT NSString* _Nonnull CryptoLoginToken(id<CryptoSigningKey> _Nullable signingKey, id<CryptoVerificationKey> _Nullable verificationKey);

FOUNDATION_EXPORT NSString* _Nonnull CryptoNewApprovalToken(id<CryptoSigningKey> _Nullable signingKey, NSString* _Nullable entityId, NSString* _Nullable clientId, NSString* _Nullable scopes, NSString* _Nullable offerCode);

FOUNDATION_EXPORT NSString* _Nonnull CryptoNewIdentityToken(id<CryptoSigningKey> _Nullable signingKey, NSString* _Nullable entityId, NSString* _Nullable source, NSString* _Nullable hash);

FOUNDATION_EXPORT NSString* _Nonnull CryptoNewRequestToken(id<CryptoSigningKey> _Nullable signingKey, NSString* _Nullable consumerId, NSString* _Nullable encryptionKey, NSString* _Nullable scopes, NSString* _Nullable offerCode);

// skipped function NewToken with unsupported parameter or return types


FOUNDATION_EXPORT id<CryptoEncryptionKey> _Nullable CryptoParseBase64EncryptionPrivateKey(NSString* _Nullable base64, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoEncryptionKey> _Nullable CryptoParseBase64EncryptionPublicKey(NSString* _Nullable base64, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoSigningKey> _Nullable CryptoParseBase64SigningKey(NSString* _Nullable base64, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoVerificationKey> _Nullable CryptoParseBase64VerificationKey(NSString* _Nullable base64, NSError* _Nullable* _Nullable error);

// skipped function ParseCipherText with unsupported parameter or return types


FOUNDATION_EXPORT id<CryptoEncryptionKey> _Nullable CryptoParseEncryptionPrivateKey(NSString* _Nullable pem, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoEncryptionKey> _Nullable CryptoParseEncryptionPublicKey(NSString* _Nullable pem, NSError* _Nullable* _Nullable error);

// skipped function ParseHashedText with unsupported parameter or return types


// skipped function ParseJwt with unsupported parameter or return types


FOUNDATION_EXPORT CryptoLoginClaims* _Nullable CryptoParseLoginToken(NSString* _Nullable tokenString, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoSigningKey> _Nullable CryptoParseSigningKey(NSString* _Nullable pem, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoVerificationKey> _Nullable CryptoParseVerificationKey(NSString* _Nullable pem, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT id<CryptoVerificationKey> _Nullable CryptoParseVerificationKeyBytes(NSData* _Nullable pemBlockBytes, NSError* _Nullable* _Nullable error);

// skipped function PlainTextValue with unsupported parameter or return types


FOUNDATION_EXPORT id<CryptoSigningKey> _Nullable CryptoSigningKeyFromPEM(NSString* _Nullable pem);

FOUNDATION_EXPORT id<CryptoVerificationKey> _Nullable CryptoVerificationKeyFromPem(NSString* _Nullable pem);

FOUNDATION_EXPORT BOOL CryptoVerifyHash(NSData* _Nullable hash, NSData* _Nullable message);

@class CryptoEncryptionKey;

@class CryptoSerializable;

@class CryptoSigningKey;

@class CryptoVerificationKey;

@interface CryptoEncryptionKey : NSObject <goSeqRefInterface, CryptoEncryptionKey> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (NSData* _Nullable)bytes;
- (NSData* _Nullable)decrypt:(NSData* _Nullable)cipher error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)decryptBase64:(NSString* _Nullable)cipher error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)encrypt:(NSData* _Nullable)plain error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)encryptAsBase64:(NSData* _Nullable)plain error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)export:(NSString* _Nullable)password error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
@end

@interface CryptoSerializable : NSObject <goSeqRefInterface, CryptoSerializable> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (NSData* _Nullable)bytes;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
@end

@interface CryptoSigningKey : NSObject <goSeqRefInterface, CryptoSigningKey> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (NSData* _Nullable)bytes;
- (NSString* _Nonnull)export:(NSString* _Nullable)password error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)sign:(NSData* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)signAsBase64:(NSData* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
- (id<CryptoVerificationKey> _Nullable)verificationKey:(NSError* _Nullable* _Nullable)error;
@end

@interface CryptoVerificationKey : NSObject <goSeqRefInterface, CryptoVerificationKey> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (NSData* _Nullable)bytes;
- (NSString* _Nonnull)string;
- (NSString* _Nonnull)stringParam;
- (BOOL)verify:(NSData* _Nullable)signature message:(NSData* _Nullable)message valid:(BOOL* _Nullable)valid error:(NSError* _Nullable* _Nullable)error;
- (BOOL)verifyBase64:(NSString* _Nullable)signature message:(NSData* _Nullable)message valid:(BOOL* _Nullable)valid error:(NSError* _Nullable* _Nullable)error;
@end

#endif
