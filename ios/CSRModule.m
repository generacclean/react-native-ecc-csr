#import "CSRModule.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

static NSString * const DEFAULT_COUNTRY = @"US";
static NSString * const DEFAULT_STATE = @"Colorado";
static NSString * const DEFAULT_LOCALITY = @"Denver";
static NSString * const DEFAULT_ORGANIZATION = @"MyOrg";
static NSString * const DEFAULT_ORGANIZATIONAL_UNIT = @"MyOrgUnit";
static NSString * const DEFAULT_IP_ADDRESS = @"10.10.10.10";
static NSString * const DEFAULT_ECC_CURVE = @"secp384r1";

@implementation CSRModule

RCT_EXPORT_MODULE(CSRModule)

RCT_EXPORT_METHOD(generateCSR:(NSDictionary *)params
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        NSString *commonName = params[@"commonName"] ?: @"";
        NSString *serialNumber = params[@"serialNumber"] ?: @"";
        NSString *country = params[@"country"] ?: DEFAULT_COUNTRY;
        NSString *state = params[@"state"] ?: DEFAULT_STATE;
        NSString *locality = params[@"locality"] ?: DEFAULT_LOCALITY;
        NSString *organization = params[@"organization"] ?: DEFAULT_ORGANIZATION;
        NSString *organizationalUnit = params[@"organizationalUnit"] ?: DEFAULT_ORGANIZATIONAL_UNIT;
        NSString *ipAddress = params[@"ipAddress"] ?: DEFAULT_IP_ADDRESS;
        NSString *dnsName = params[@"dnsName"];
        NSString *curve = params[@"curve"] ?: DEFAULT_ECC_CURVE;
        NSString *phoneInfo = params[@"phoneInfo"]; 
        NSString *privateKeyAlias = params[@"privateKeyAlias"];
        
        // Default: false (software keys - matches Android behavior)
        // For P-256: can be set to true to try Secure Enclave
        // For P-384/P-521: always false (Secure Enclave doesn't support them)
        BOOL useHardwareKey = params[@"useHardwareKey"] ? [params[@"useHardwareKey"] boolValue] : NO;
        
        if (commonName.length == 0) {
            reject(@"INVALID_PARAM", @"commonName is required", nil);
            return;
        }
        
        if (!privateKeyAlias || privateKeyAlias.length == 0) {
            reject(@"INVALID_PARAM", @"privateKeyAlias is required", nil);
            return;
        }
        
        NSString *normalizedCurve = [self normalizeCurveName:curve];
        
        NSError *error = nil;
        NSDictionary *keyPair = [self generateECKeyPairForCurve:normalizedCurve 
                                                        withAlias:privateKeyAlias 
                                                   useHardwareKey:useHardwareKey
                                                            error:&error];
        if (error) {
            reject(@"KEY_GENERATION_ERROR", error.localizedDescription, error);
            return;
        }
        
        SecKeyRef privateKey = (__bridge SecKeyRef)keyPair[@"privateKey"];
        SecKeyRef publicKey = (__bridge SecKeyRef)keyPair[@"publicKey"];
        BOOL isHardwareBacked = [keyPair[@"isHardwareBacked"] boolValue];
        BOOL actualUseHardwareKey = [keyPair[@"useHardwareKey"] boolValue];
        
        NSData *publicKeyData = [self exportPublicKey:publicKey error:&error];
        if (error) {
            reject(@"PUBLIC_KEY_ERROR", error.localizedDescription, error);
            return;
        }
        
        NSData *csrData = [self buildCSRWithSubject:@{
            @"CN": commonName,
            @"serialNumber": serialNumber,
            @"C": country,
            @"ST": state,
            @"L": locality,
            @"O": organization,
            @"OU": organizationalUnit
        }
                                          publicKey:publicKey
                                         privateKey:privateKey
                                              curve:normalizedCurve
                                          ipAddress:ipAddress
                                            dnsName:dnsName
                                          phoneInfo:phoneInfo 
                                              error:&error];
        
        if (error) {
            reject(@"CSR_GENERATION_ERROR", error.localizedDescription, error);
            return;
        }
        
        NSString *csrPEM = [self convertToPEM:csrData label:@"CERTIFICATE REQUEST"];
        NSString *publicKeyPEM = [self convertToPEM:publicKeyData label:@"PUBLIC KEY"];
        
        resolve(@{
            @"csr": csrPEM,
            @"privateKeyAlias": privateKeyAlias,
            @"publicKey": publicKeyPEM,
            @"isHardwareBacked": @(isHardwareBacked),
            @"useHardwareKey": @(actualUseHardwareKey)
        });
        
    } @catch (NSException *exception) {
        reject(@"EXCEPTION", exception.reason, nil);
    }
}

RCT_EXPORT_METHOD(deleteKey:(NSString *)privateKeyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        BOOL success = [self deleteKeyWithAlias:privateKeyAlias];
        resolve(@(success));
    } @catch (NSException *exception) {
        reject(@"DELETE_KEY_ERROR", exception.reason, nil);
    }
}

RCT_EXPORT_METHOD(keyExists:(NSString *)privateKeyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        BOOL exists = [self keyExistsWithAlias:privateKeyAlias];
        resolve(@(exists));
    } @catch (NSException *exception) {
        reject(@"KEY_EXISTS_ERROR", exception.reason, nil);
    }
}

RCT_EXPORT_METHOD(getPublicKey:(NSString *)privateKeyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        NSError *error = nil;
        NSString *publicKeyPEM = [self getPublicKeyForAlias:privateKeyAlias error:&error];
        
        if (error) {
            reject(@"GET_PUBLIC_KEY_ERROR", error.localizedDescription, error);
            return;
        }
        
        resolve(publicKeyPEM);
    } @catch (NSException *exception) {
        reject(@"GET_PUBLIC_KEY_ERROR", exception.reason, nil);
    }
}

#pragma mark - Helper Methods

- (NSString *)normalizeCurveName:(NSString *)curveName {
    if ([curveName isEqualToString:@"secp256r1"]) {
        return @"P-256";
    } else if ([curveName isEqualToString:@"secp384r1"]) {
        return @"P-384";
    } else if ([curveName isEqualToString:@"secp521r1"]) {
        return @"P-521";
    }
    return @"P-384";
}

- (BOOL)isKeyHardwareBacked:(SecKeyRef)key {
    if (key == NULL) {
        return NO;
    }
    
    NSDictionary *attributes = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
    NSString *tokenID = attributes[(id)kSecAttrTokenID];
    
    return [tokenID isEqualToString:(NSString *)kSecAttrTokenIDSecureEnclave];
}

- (BOOL)deleteKeyWithAlias:(NSString *)alias {
    NSData *tag = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
    };
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return status == errSecSuccess || status == errSecItemNotFound;
}

- (BOOL)keyExistsWithAlias:(NSString *)alias {
    NSData *tag = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecReturnRef: @YES,
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (result) {
        CFRelease(result);
    }
    
    return status == errSecSuccess;
}

- (NSString *)getPublicKeyForAlias:(NSString *)alias error:(NSError **)error {
    NSData *tag = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecReturnRef: @YES,
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:@"CSRModule" 
                                         code:status 
                                     userInfo:@{NSLocalizedDescriptionKey: @"Key not found"}];
        }
        return nil;
    }
    
    SecKeyRef privateKey = (SecKeyRef)result;
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFRelease(result);
    
    if (!publicKey) {
        if (error) {
            *error = [NSError errorWithDomain:@"CSRModule" 
                                         code:-1 
                                     userInfo:@{NSLocalizedDescriptionKey: @"Could not extract public key"}];
        }
        return nil;
    }
    
    NSData *publicKeyData = [self exportPublicKey:publicKey error:error];
    CFRelease(publicKey);
    
    if (!publicKeyData) {
        return nil;
    }
    
    return [self convertToPEM:publicKeyData label:@"PUBLIC KEY"];
}

#pragma mark - Key Generation

- (NSDictionary *)generateECKeyPairForCurve:(NSString *)curveName 
                                  withAlias:(NSString *)alias 
                             useHardwareKey:(BOOL)useHardwareKey
                                      error:(NSError **)error {
    int keySize = 384;
    if ([curveName isEqualToString:@"P-256"]) {
        keySize = 256;
    } else if ([curveName isEqualToString:@"P-521"]) {
        keySize = 521;
    }
    
    NSData *tagData = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    BOOL isHardwareBacked = NO;
    BOOL actualUseHardwareKey = NO;
    SecKeyRef privateKey = NULL;
    
    // Secure Enclave ONLY supports P-256
    // For P-384/P-521: always use software
    // For P-256: respect useHardwareKey parameter
    
    if (keySize == 256 && useHardwareKey) {
        NSDictionary *secureEnclaveParams = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @(keySize),
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecPrivateKeyAttrs: @{
                (id)kSecAttrIsPermanent: @YES,
                (id)kSecAttrApplicationTag: tagData,
            }
        };
        
        CFErrorRef cfError = NULL;
        privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)secureEnclaveParams, &cfError);
        
        if (privateKey != NULL) {
            isHardwareBacked = YES;
            actualUseHardwareKey = YES;
            NSLog(@"✅ P-256 key created in Secure Enclave (hardware-backed)");
        } else {
            NSLog(@"⚠️ Secure Enclave failed, falling back to software");
            if (cfError) {
                CFRelease(cfError);
            }
        }
    }
    
    if (privateKey == NULL) {
        NSDictionary *softwareParams = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @(keySize),
            (id)kSecPrivateKeyAttrs: @{
                (id)kSecAttrIsPermanent: @YES,
                (id)kSecAttrApplicationTag: tagData,
            }
        };
        
        CFErrorRef cfError = NULL;
        privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)softwareParams, &cfError);
        
        if (cfError) {
            if (error) {
                *error = (__bridge_transfer NSError *)cfError;
            }
            return nil;
        }
        
        isHardwareBacked = NO;
        actualUseHardwareKey = NO;
        
        if (keySize == 256) {
            NSLog(@"ℹ️ P-256 key created in software");
        } else {
            NSLog(@"ℹ️ P-%d key created in software (Secure Enclave unsupported)", keySize);
        }
    }
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    
    return @{
        @"privateKey": (__bridge_transfer id)privateKey,
        @"publicKey": (__bridge_transfer id)publicKey,
        @"isHardwareBacked": @(isHardwareBacked),
        @"useHardwareKey": @(actualUseHardwareKey)
    };
}

- (NSData *)exportPublicKey:(SecKeyRef)publicKey error:(NSError **)error {
    CFErrorRef cfError = NULL;
    NSData *keyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(publicKey, &cfError);
    
    if (cfError) {
        if (error) {
            *error = (__bridge_transfer NSError *)cfError;
        }
        return nil;
    }
    
    NSData *spki = [self wrapPublicKeyInSPKI:keyData curve:[self getCurveFromKey:publicKey]];
    return spki;
}

- (NSString *)getCurveFromKey:(SecKeyRef)key {
    NSDictionary *attributes = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
    NSNumber *keySize = attributes[(id)kSecAttrKeySizeInBits];
    
    if ([keySize intValue] == 256) return @"P-256";
    if ([keySize intValue] == 384) return @"P-384";
    if ([keySize intValue] == 521) return @"P-521";
    
    return @"P-384";
}

#pragma mark - CSR Building

- (NSData *)buildCSRWithSubject:(NSDictionary *)subject
                      publicKey:(SecKeyRef)publicKey
                     privateKey:(SecKeyRef)privateKey
                          curve:(NSString *)curve
                      ipAddress:(NSString *)ipAddress
                        dnsName:(NSString *)dnsName
                      phoneInfo:(NSString *)phoneInfo 
                          error:(NSError **)error {
    
    NSData *subjectDN = [self encodeDN:subject];
    NSData *publicKeyInfo = [self exportPublicKey:publicKey error:error];
    if (*error) return nil;
    
    NSData *extensions = [self buildExtensions:ipAddress dnsName:dnsName phoneInfo:phoneInfo];
    NSData *attributes = [self buildAttributes:extensions];
    
    NSData *certRequestInfo = [self buildCertificationRequestInfo:subjectDN
                                                    publicKeyInfo:publicKeyInfo
                                                       attributes:attributes];
    
    NSData *signature = [self signData:certRequestInfo withPrivateKey:privateKey error:error];
    if (*error) return nil;
    
    NSData *csr = [self buildFinalCSR:certRequestInfo signature:signature curve:curve];
    
    return csr;
}

- (NSData *)buildCertificationRequestInfo:(NSData *)subject
                            publicKeyInfo:(NSData *)publicKeyInfo
                               attributes:(NSData *)attributes {
    NSMutableData *certRequestInfo = [NSMutableData data];
    
    NSData *version = [self encodeInteger:0];
    
    [certRequestInfo appendData:version];
    [certRequestInfo appendData:subject];
    [certRequestInfo appendData:publicKeyInfo];
    [certRequestInfo appendData:attributes];
    
    return [self wrapInSequence:certRequestInfo];
}

- (NSData *)buildFinalCSR:(NSData *)certRequestInfo
                signature:(NSData *)signature
                    curve:(NSString *)curve {
    NSMutableData *csr = [NSMutableData data];
    
    [csr appendData:certRequestInfo];
    
    NSData *signatureAlgorithm = [self encodeSignatureAlgorithm];
    [csr appendData:signatureAlgorithm];
    
    NSData *signatureBitString = [self encodeBitString:signature];
    [csr appendData:signatureBitString];
    
    return [self wrapInSequence:csr];
}

#pragma mark - DN Encoding

- (NSData *)encodeDN:(NSDictionary *)subject {
    NSMutableData *dn = [NSMutableData data];
    
    NSArray *order = @[@"C", @"ST", @"L", @"O", @"OU", @"CN", @"serialNumber"];
    
    for (NSString *key in order) {
        NSString *value = subject[key];
        if (value && value.length > 0) {
            NSData *rdn = [self encodeRDN:key value:value];
            [dn appendData:rdn];
        }
    }
    
    return [self wrapInSequence:dn];
}

- (NSData *)encodeRDN:(NSString *)key value:(NSString *)value {
    NSData *oid = [self getOIDForAttribute:key];
    
    NSData *stringValue;
    
    if ([key isEqualToString:@"C"] || [key isEqualToString:@"serialNumber"]) {
        stringValue = [self encodePrintableString:value];
    } else {
        stringValue = [self encodeUTF8String:value];
    }
    
    NSMutableData *atav = [NSMutableData data];
    [atav appendData:oid];
    [atav appendData:stringValue];
    NSData *atavSeq = [self wrapInSequence:atav];
    
    return [self wrapInSet:atavSeq];
}

- (NSData *)getOIDForAttribute:(NSString *)attribute {
    NSDictionary *oidMap = @{
        @"C": @"2.5.4.6",
        @"ST": @"2.5.4.8",
        @"L": @"2.5.4.7",
        @"O": @"2.5.4.10",
        @"OU": @"2.5.4.11",
        @"CN": @"2.5.4.3",
        @"serialNumber": @"2.5.4.5"
    };
    
    return [self encodeOID:oidMap[attribute]];
}

#pragma mark - Extensions

- (NSData *)buildExtensions:(NSString *)ipAddress dnsName:(NSString *)dnsName phoneInfo:(NSString *)phoneInfo {
    NSMutableData *extensions = [NSMutableData data];
    
    NSData *keyUsage = [self buildKeyUsageExtension];
    [extensions appendData:keyUsage];
    
    NSData *extKeyUsage = [self buildExtendedKeyUsageExtension];
    [extensions appendData:extKeyUsage];
    
    if ((ipAddress && ipAddress.length > 0) || (dnsName && dnsName.length > 0) || (phoneInfo && phoneInfo.length > 0)) {
        NSData *san = [self buildSubjectAltNameExtension:ipAddress dnsName:dnsName phoneInfo:phoneInfo];
        [extensions appendData:san];
    }
    
    return [self wrapInSequence:extensions];
}

- (NSData *)buildKeyUsageExtension {
    unsigned char bitStringValue[] = {0x03, 0x88};
    
    NSMutableData *encodedBitString = [NSMutableData data];
    unsigned char tag = 0x03;
    unsigned char length = 0x02;
    [encodedBitString appendBytes:&tag length:1];
    [encodedBitString appendBytes:&length length:1];
    [encodedBitString appendBytes:bitStringValue length:2];
    
    return [self buildExtension:@"2.5.29.15" critical:YES value:encodedBitString];
}

- (NSData *)buildExtendedKeyUsageExtension {
    NSData *clientAuthOID = [self encodeOID:@"1.3.6.1.5.5.7.3.2"];
    NSData *sequence = [self wrapInSequence:clientAuthOID];
    
    return [self buildExtension:@"2.5.29.37" critical:NO value:sequence];
}

- (NSData *)buildSubjectAltNameExtension:(NSString *)ipAddress dnsName:(NSString *)dnsName phoneInfo:(NSString *)phoneInfo {
    NSMutableData *sanData = [NSMutableData data];

    if (dnsName && dnsName.length > 0) {
        @try {
            NSArray *dnsNames = [dnsName componentsSeparatedByString:@","];
            
            for (NSString *dns in dnsNames) {
                NSString *trimmedDns = [dns stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                
                if (trimmedDns.length > 0) {
                    NSData *dnsData = [trimmedDns dataUsingEncoding:NSUTF8StringEncoding];
                    
                    NSMutableData *dnsTag = [NSMutableData data];
                    unsigned char tag = 0x82;
                    
                    NSData *lengthData = [self encodeLength:dnsData.length];
                    
                    [dnsTag appendBytes:&tag length:1];
                    [dnsTag appendData:lengthData];
                    [dnsTag appendData:dnsData];
                    
                    [sanData appendData:dnsTag];
                }
            }
        } @catch (NSException *exception) {
            NSLog(@"⚠️ Failed to add DNS name to SAN: %@", exception.reason);
        }
    }
    
    if (ipAddress && ipAddress.length > 0) {
        NSArray *octets = [ipAddress componentsSeparatedByString:@"."];
        if (octets.count == 4) {
            unsigned char ipBytes[4];
            for (int i = 0; i < 4; i++) {
                ipBytes[i] = (unsigned char)[octets[i] intValue];
            }
            
            NSMutableData *ipTag = [NSMutableData data];
            unsigned char tag = 0x87;
            unsigned char length = 0x04;
            [ipTag appendBytes:&tag length:1];
            [ipTag appendBytes:&length length:1];
            [ipTag appendBytes:ipBytes length:4];
            
            [sanData appendData:ipTag];
        }
    }
    
    if (phoneInfo && phoneInfo.length > 0) {
        @try {
            NSString *trimmedPhoneInfo = [phoneInfo stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            
            if (trimmedPhoneInfo.length > 0) {
                NSString *uriValue = [NSString stringWithFormat:@"phone:%@", trimmedPhoneInfo];
                NSData *uriData = [uriValue dataUsingEncoding:NSUTF8StringEncoding];
                
                NSMutableData *uriTag = [NSMutableData data];
                unsigned char tag = 0x86;
                
                NSData *lengthData = [self encodeLength:uriData.length];
                
                [uriTag appendBytes:&tag length:1];
                [uriTag appendData:lengthData];
                [uriTag appendData:uriData];
                
                [sanData appendData:uriTag];
            }
        } @catch (NSException *exception) {
            NSLog(@"⚠️ Failed to add phone info to SAN: %@", exception.reason);
        }
    }
    
    NSData *sanSequence = [self wrapInSequence:sanData];
    
    return [self buildExtension:@"2.5.29.17" critical:NO value:sanSequence];
}

- (NSData *)buildExtension:(NSString *)oidString critical:(BOOL)critical value:(NSData *)value {
    NSMutableData *extension = [NSMutableData data];
    
    [extension appendData:[self encodeOID:oidString]];
    
    if (critical) {
        NSData *criticalBool = [NSData dataWithBytes:(unsigned char[]){0x01, 0x01, 0xFF} length:3];
        [extension appendData:criticalBool];
    }
    
    [extension appendData:[self encodeOctetString:value]];
    
    return [self wrapInSequence:extension];
}

- (NSData *)buildAttributes:(NSData *)extensions {
    NSData *extReqOID = [self encodeOID:@"1.2.840.113549.1.9.14"];
    NSData *extSet = [self wrapInSet:extensions];
    
    NSMutableData *attribute = [NSMutableData data];
    [attribute appendData:extReqOID];
    [attribute appendData:extSet];
    NSData *attrSeq = [self wrapInSequence:attribute];
    
    return [self wrapInContext:attrSeq tag:0];
}

#pragma mark - Signing

- (NSData *)signData:(NSData *)data withPrivateKey:(SecKeyRef)privateKey error:(NSError **)error {
    NSMutableData *hash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash.mutableBytes);
    
    CFErrorRef cfError = NULL;
    NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(
        privateKey,
        kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
        (__bridge CFDataRef)hash,
        &cfError
    );
    
    if (cfError) {
        if (error) {
            *error = (__bridge_transfer NSError *)cfError;
        }
        return nil;
    }
    
    return signature;
}

- (NSData *)encodeSignatureAlgorithm {
    NSData *oid = [self encodeOID:@"1.2.840.10045.4.3.2"];
    return [self wrapInSequence:oid];
}

#pragma mark - Public Key Info

- (NSData *)wrapPublicKeyInSPKI:(NSData *)publicKeyData curve:(NSString *)curve {
    NSMutableData *spki = [NSMutableData data];
    
    NSData *algorithm = [self encodeAlgorithmIdentifier:curve];
    [spki appendData:algorithm];
    
    NSData *publicKeyBitString = [self encodeBitString:publicKeyData];
    [spki appendData:publicKeyBitString];
    
    return [self wrapInSequence:spki];
}

- (NSData *)encodeAlgorithmIdentifier:(NSString *)curve {
    NSMutableData *algId = [NSMutableData data];
    
    NSData *eccOID = [self encodeOID:@"1.2.840.10045.2.1"];
    [algId appendData:eccOID];
    
    NSString *curveOID = @"1.2.840.10045.3.1.7";
    if ([curve isEqualToString:@"P-384"]) {
        curveOID = @"1.3.132.0.34";
    } else if ([curve isEqualToString:@"P-521"]) {
        curveOID = @"1.3.132.0.35";
    }
    
    NSData *curveOIDData = [self encodeOID:curveOID];
    [algId appendData:curveOIDData];
    
    return [self wrapInSequence:algId];
}

#pragma mark - ASN.1 Encoding Primitives

- (NSData *)encodeInteger:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    unsigned char tag = 0x02;
    unsigned char length = 0x01;
    unsigned char val = (unsigned char)value;
    
    [data appendBytes:&tag length:1];
    [data appendBytes:&length length:1];
    [data appendBytes:&val length:1];
    
    return data;
}

- (NSData *)encodeOID:(NSString *)oidString {
    NSArray *components = [oidString componentsSeparatedByString:@"."];
    NSMutableData *oidData = [NSMutableData data];
    
    unsigned char firstByte = [components[0] intValue] * 40 + [components[1] intValue];
    [oidData appendBytes:&firstByte length:1];
    
    for (NSInteger i = 2; i < components.count; i++) {
        NSInteger value = [components[i] integerValue];
        NSData *encoded = [self encodeOIDComponent:value];
        [oidData appendData:encoded];
    }
    
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x06;
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:oidData.length]];
    [result appendData:oidData];
    
    return result;
}

- (NSData *)encodeOIDComponent:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    
    if (value < 128) {
        unsigned char byte = (unsigned char)value;
        [data appendBytes:&byte length:1];
    } else {
        NSMutableArray *bytes = [NSMutableArray array];
        while (value > 0) {
            [bytes insertObject:@(value & 0x7F) atIndex:0];
            value >>= 7;
        }
        
        for (NSInteger i = 0; i < bytes.count; i++) {
            unsigned char byte = [bytes[i] unsignedCharValue];
            if (i < bytes.count - 1) {
                byte |= 0x80;
            }
            [data appendBytes:&byte length:1];
        }
    }
    
    return data;
}

- (NSData *)encodePrintableString:(NSString *)string {
    NSData *stringData = [string dataUsingEncoding:NSASCIIStringEncoding];
    NSMutableData *result = [NSMutableData data];
    
    unsigned char tag = 0x13;
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:stringData.length]];
    [result appendData:stringData];
    
    return result;
}

- (NSData *)encodeUTF8String:(NSString *)string {
    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [NSMutableData data];
    
    unsigned char tag = 0x0C;
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:stringData.length]];
    [result appendData:stringData];
    
    return result;
}

- (NSData *)encodeOctetString:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x04;
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)encodeBitString:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x03;
    unsigned char unusedBits = 0x00;
    
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length + 1]];
    [result appendBytes:&unusedBits length:1];
    [result appendData:data];
    
    return result;
}

- (NSData *)wrapInSequence:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x30;
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)wrapInSet:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x31;
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)wrapInContext:(NSData *)data tag:(unsigned char)contextTag {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0xA0 | contextTag;
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)encodeLength:(NSUInteger)length {
    NSMutableData *result = [NSMutableData data];
    
    if (length < 128) {
        unsigned char byte = (unsigned char)length;
        [result appendBytes:&byte length:1];
    } else {
        NSMutableArray *bytes = [NSMutableArray array];
        NSUInteger temp = length;
        while (temp > 0) {
            [bytes insertObject:@(temp & 0xFF) atIndex:0];
            temp >>= 8;
        }
        
        unsigned char firstByte = 0x80 | bytes.count;
        [result appendBytes:&firstByte length:1];
        
        for (NSNumber *byte in bytes) {
            unsigned char b = [byte unsignedCharValue];
            [result appendBytes:&b length:1];
        }
    }
    
    return result;
}

#pragma mark - PEM Conversion

- (NSString *)convertToPEM:(NSData *)data label:(NSString *)label {
    NSString *base64 = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    base64 = [base64 stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    
    return [NSString stringWithFormat:@"-----BEGIN %@-----\n%@\n-----END %@-----",
            label, base64, label];
}

@end
