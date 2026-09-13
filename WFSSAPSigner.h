#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const WFSSAPSignerErrorDomain;

typedef NS_ENUM(NSInteger, WFSSAPSignerErrorCode) {
	WFSSAPSignerErrorInvalidConfig = 1,
	WFSSAPSignerErrorSetupFailed,
	WFSSAPSignerErrorSigningFailed,
	WFSSAPSignerErrorClosed,
};

@interface WFSSAPConfig : NSObject
@property (nonatomic, copy) NSString *setupURL;
@property (nonatomic, copy) NSString *certificateURL;
@property (nonatomic, assign) uint32_t version;
@property (nonatomic, strong) NSData *hardwareID;
@end

@protocol WFSSAPActionSigner <NSObject>
- (nullable NSData *)sign:(NSData *)input error:(NSError **)error;
- (void)close;
@end

@interface WFSSAPSigner : NSObject <WFSSAPActionSigner>

+ (nullable instancetype)signerWithConfig:(WFSSAPConfig *)config
                                    error:(NSError **)error;

- (nullable instancetype)initWithConfig:(WFSSAPConfig *)config
                                  error:(NSError **)error;

+ (nullable NSData *)hardwareIDFromGUID:(NSString *)guid;

@end

NS_ASSUME_NONNULL_END
