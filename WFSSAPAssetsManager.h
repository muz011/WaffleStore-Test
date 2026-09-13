#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, WFSSAPAssetsState) {
    WFSSAPAssetsStateUnknown = 0,
    WFSSAPAssetsStateDownloading,
    WFSSAPAssetsStateExtracting,
    WFSSAPAssetsStateReady,
    WFSSAPAssetsStateFailed,
};

@interface WFSSAPAssetsManager : NSObject

@property (nonatomic, readonly) WFSSAPAssetsState state;
@property (nonatomic, readonly) float progress;
@property (nonatomic, readonly, copy, nullable) NSString *statusMessage;
@property (nonatomic, readonly) int64_t bytesReceived;
@property (nonatomic, readonly) int64_t totalBytes;
@property (nonatomic, readonly) double bytesPerSecond;
@property (nonatomic, readonly, copy, nullable) NSString *estimatedTimeRemaining;

+ (instancetype)sharedManager;

- (BOOL)assetsReady;
- (nullable NSString *)pathForAsset:(NSString *)name;

- (void)downloadWithProgress:(void (^)(float progress, NSString *status, NSString *speed, NSString *eta))progressHandler
                   completion:(void (^)(BOOL success, NSError * _Nullable error))completion;

- (void)cancel;

- (nullable NSData *)coreFPData;
- (nullable NSData *)commerceCoreData;
- (nullable NSData *)commerceKitData;
- (nullable NSData *)coreFPICXSData;

@end

NS_ASSUME_NONNULL_END
