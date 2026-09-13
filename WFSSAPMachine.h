#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WFSSAPMachine : NSObject

+ (nullable instancetype)openWithCoreFP:(NSData *)coreFP
                           commerceCore:(NSData *)commerceCore
                           commerceKit:(NSData *)commerceKit
                             coreFPICXS:(NSData *)coreFPICXS
                                  error:(NSError **)error;

- (nullable NSNumber *)initializeWithHardwareID:(NSData *)hardwareID
                                          error:(NSError **)error;

- (nullable NSDictionary *)exchangeWithVersion:(uint32_t)version
                                    hardwareID:(NSData *)hardwareID
                                       context:(uint64_t)context
                                         input:(NSData *)input
                                         error:(NSError **)error;

- (nullable NSData *)signWithContext:(uint64_t)context
                              input:(NSData *)input
                              error:(NSError **)error;

- (BOOL)teardownWithContext:(uint64_t)context error:(NSError **)error;

- (nullable NSString *)macAddress;

- (void)close;

@end

NS_ASSUME_NONNULL_END
