#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CSRResolveBlock)(id _Nullable result);
typedef void (^CSRRejectBlock)(NSString *code, NSString * _Nullable message, NSError * _Nullable error);

/**
 * ECC key pair and CSR generation, with no dependency on React Native or Expo.
 *
 * The JS-facing module is the Expo module in CSRModule.swift, which only adapts arguments and
 * promises. Everything that decides behaviour - validation, key storage, error codes, response
 * shape - lives here.
 *
 * Each method calls exactly one of resolve/reject exactly once, synchronously, on the calling
 * thread. The codes passed to reject are part of the JS contract (callers match on error.code), so
 * treat them as API.
 */
@interface CSRCore : NSObject

- (void)generateCSR:(NSDictionary<NSString *, id> *)params resolve:(CSRResolveBlock)resolve reject:(CSRRejectBlock)reject;
- (void)deleteKey:(NSString *)privateKeyAlias resolve:(CSRResolveBlock)resolve reject:(CSRRejectBlock)reject;
- (void)keyExists:(NSString *)privateKeyAlias resolve:(CSRResolveBlock)resolve reject:(CSRRejectBlock)reject;
- (void)getPublicKey:(NSString *)privateKeyAlias resolve:(CSRResolveBlock)resolve reject:(CSRRejectBlock)reject;
- (void)getHardwareKeystoreCapabilities:(CSRResolveBlock)resolve reject:(CSRRejectBlock)reject;

@end

NS_ASSUME_NONNULL_END
