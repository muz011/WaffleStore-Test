#ifndef WFSSAPShims_h
#define WFSSAPShims_h

#import <Foundation/Foundation.h>
#import "WFSUnicorn.h"

NS_ASSUME_NONNULL_BEGIN

@interface WFSSAPShims : NSObject

@property (nonatomic, assign, readonly) BOOL faulted;
@property (nonatomic, strong, readonly, nullable) NSError *fault;

- (nullable instancetype)initWithEngine:(uc_engine)engine
                            coreExports:(NSDictionary<NSString *, NSNumber *> *)coreExports
                                   icxs:(nullable NSData *)icxs
                                  error:(NSError **)error;

- (uint64_t)resolveSymbol:(NSString *)name error:(NSError **)error;
- (void)dispatchAtAddress:(uint64_t)address;
- (void)resetFault;
- (void)close;

@end

NS_ASSUME_NONNULL_END

#endif
