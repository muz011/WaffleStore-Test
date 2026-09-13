#import "WFSSAPAssetsManager.h"
#import <bzlib.h>
#import <zlib.h>
#import <objc/runtime.h>

static NSString *const kWFSPackageURL = @"https://swcdn.apple.com/content/downloads/27/34/041-98128-A_SYPWICN3KH/5dqkl4rqgbsr18yzy61yeie9g3cmjc5hiv/OSXUpd10.9.pkg";

static NSString *const kWFSCoreFPPath = @"./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP";
static NSString *const kWFSCommerceCorePath = @"./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Frameworks/CommerceCore.framework/Versions/A/CommerceCore";
static NSString *const kWFSCommerceKitPath = @"./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/CommerceKit";
static NSString *const kWFSCoreFPIXXSPath = @"./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP.icxs";

static const int64_t kWFSPayloadBZOffset = 0x352F40D5;
static const int64_t kWFSCPIOOffset = 0x3A4;

@interface WFSTOCXMLParserDelegate : NSObject <NSXMLParserDelegate>
@property (nonatomic, assign) int64_t headerSize;
@property (nonatomic, assign) int64_t payloadOffset;
@property (nonatomic, assign) int64_t payloadSize;
@end

@implementation WFSTOCXMLParserDelegate {
    NSString *_currentName;
    int64_t _currentOffset;
    int64_t _currentSize;
    NSMutableString *_currentText;
}

- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName attributes:(NSDictionary<NSString *,NSString *> *)attributeDict {
    if ([elementName isEqualToString:@"file"]) {
        _currentName = nil;
        _currentOffset = 0;
        _currentSize = 0;
    }
    _currentText = [NSMutableString string];
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string {
    [_currentText appendString:string];
}

- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName {
    NSString *trimmed = [_currentText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([elementName isEqualToString:@"name"]) {
        _currentName = trimmed;
    } else if ([elementName isEqualToString:@"Offset"]) {
        _currentOffset = [trimmed longLongValue];
    } else if ([elementName isEqualToString:@"Length"]) {
        _currentSize = [trimmed longLongValue];
    } else if ([elementName isEqualToString:@"file"]) {
        if ([_currentName isEqualToString:@"Payload"] && _currentOffset > 0 && _currentSize > 0) {
            _payloadOffset = _currentOffset + _headerSize;
            _payloadSize = _currentSize;
        }
    }
    _currentText = nil;
}

@end

@interface WFSSAPAssetsManager () <NSURLSessionDataDelegate>
@property (nonatomic, assign) WFSSAPAssetsState state;
@property (nonatomic, assign) float progress;
@property (nonatomic, copy, nullable) NSString *statusMessage;
@property (nonatomic, assign) int64_t bytesReceived;
@property (nonatomic, assign) int64_t totalBytes;
@property (nonatomic, assign) double bytesPerSecond;
@property (nonatomic, copy, nullable) NSString *estimatedTimeRemaining;
@property (nonatomic, strong, nullable) NSURLSession *session;
@property (nonatomic, assign) BOOL cancelled;
@property (nonatomic, strong, nullable) dispatch_source_t speedTimer;
@end

@implementation WFSSAPAssetsManager {
    int64_t _lastBytesReceived;
    CFAbsoluteTime _lastSpeedTime;
    NSMutableData *_downloadBuffer;
}

+ (instancetype)sharedManager {
    static WFSSAPAssetsManager *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[WFSSAPAssetsManager alloc] init];
    });
    return shared;
}

- (NSString *)assetsDirectory {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/SAPAssets"];
}

- (BOOL)assetsReady {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [self assetsDirectory];
    return [fm fileExistsAtPath:[dir stringByAppendingPathComponent:@"CoreFP.bin"]] &&
           [fm fileExistsAtPath:[dir stringByAppendingPathComponent:@"CommerceCore.bin"]] &&
           [fm fileExistsAtPath:[dir stringByAppendingPathComponent:@"CommerceKit.bin"]] &&
           [fm fileExistsAtPath:[dir stringByAppendingPathComponent:@"CoreFP_icxs.bin"]];
}

- (nullable NSString *)pathForAsset:(NSString *)name {
    NSString *path = [[self assetsDirectory] stringByAppendingPathComponent:[name stringByAppendingPathExtension:@"bin"]];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return path;
    return nil;
}

- (nullable NSData *)coreFPData {
    return [NSData dataWithContentsOfFile:[self pathForAsset:@"CoreFP"]];
}

- (nullable NSData *)commerceCoreData {
    return [NSData dataWithContentsOfFile:[self pathForAsset:@"CommerceCore"]];
}

- (nullable NSData *)commerceKitData {
    return [NSData dataWithContentsOfFile:[self pathForAsset:@"CommerceKit"]];
}

- (nullable NSData *)coreFPICXSData {
    return [NSData dataWithContentsOfFile:[self pathForAsset:@"CoreFP_icxs"]];
}

#pragma mark - Download

- (void)downloadWithProgress:(void (^)(float progress, NSString *status, NSString *speed, NSString *eta))progressHandler
                   completion:(void (^)(BOOL success, NSError * _Nullable error))completion
{
    if ([self assetsReady]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(YES, nil);
        });
        return;
    }

    self.cancelled = NO;
    self.bytesReceived = 0;
    self.totalBytes = 0;
    self.bytesPerSecond = 0;
    self.progress = 0;
    _lastBytesReceived = 0;
    _lastSpeedTime = CFAbsoluteTimeGetCurrent();
    _downloadBuffer = [NSMutableData data];

    NSString *dir = [self assetsDirectory];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.timeoutIntervalForRequest = 30;
    config.timeoutIntervalForResource = 3600;
    self.session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];

    NSURL *url = [NSURL URLWithString:kWFSPackageURL];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [[self.session dataTaskWithRequest:request] resume];

    self.state = WFSSAPAssetsStateDownloading;
    self.statusMessage = @"Downloading SAP assets from Apple…";

    objc_setAssociatedObject(self, "completionBlock", [completion copy], OBJC_ASSOCIATION_COPY_NONATOMIC);

    __weak typeof(self) weakSelf = self;
    self.speedTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(self.speedTimer, DISPATCH_TIME_NOW, NSEC_PER_SEC / 4, NSEC_PER_MSEC * 100);
    dispatch_source_set_event_handler(self.speedTimer, ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self || self.cancelled) return;

        CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
        CFAbsoluteTime elapsed = now - self->_lastSpeedTime;
        if (elapsed >= 0.5) {
            int64_t deltaBytes = self.bytesReceived - self->_lastBytesReceived;
            self.bytesPerSecond = (double)deltaBytes / elapsed;
            self->_lastBytesReceived = self.bytesReceived;
            self->_lastSpeedTime = now;

            if (self.totalBytes > 0) {
                self.progress = (float)self.bytesReceived / (float)self.totalBytes;
                int64_t remaining = self.totalBytes - self.bytesReceived;
                double etaSeconds = remaining / MAX(self.bytesPerSecond, 1.0);
                self.estimatedTimeRemaining = [self formatDuration:etaSeconds];
            } else {
                self.progress = 0;
                self.estimatedTimeRemaining = @"calculating…";
            }

            if (progressHandler) {
                progressHandler(self.progress,
                                self.statusMessage ?: @"",
                                [self formatBytesPerSecond:self.bytesPerSecond],
                                self.estimatedTimeRemaining ?: @"");
            }
        }
    });
    dispatch_resume(self.speedTimer);
}

- (void)cancel {
    self.cancelled = YES;
    if (self.speedTimer) {
        dispatch_source_cancel(self.speedTimer);
        self.speedTimer = nil;
    }
    [self.session invalidateAndCancel];
    self.session = nil;
    self.state = WFSSAPAssetsStateFailed;
    self.statusMessage = @"Cancelled";
    void (^completion)(BOOL, NSError *) = objc_getAssociatedObject(self, "completionBlock");
    if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(NO, [NSError errorWithDomain:@"WFSSAPAssetsManager" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Download cancelled."}]);
        });
        objc_setAssociatedObject(self, "completionBlock", nil, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }
}

#pragma mark - NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    if (self.cancelled) {
        completionHandler(NSURLSessionResponseCancel);
        return;
    }
    self.totalBytes = response.expectedContentLength;
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    if (self.cancelled) return;
    self.bytesReceived += data.length;
    [_downloadBuffer appendData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (self.speedTimer) {
        dispatch_source_cancel(self.speedTimer);
        self.speedTimer = nil;
    }

    if (self.cancelled) return;

    if (error) {
        self.state = WFSSAPAssetsStateFailed;
        self.statusMessage = error.localizedDescription;
        void (^completion)(BOOL, NSError *) = objc_getAssociatedObject(self, "completionBlock");
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(NO, error);
            });
            objc_setAssociatedObject(self, "completionBlock", nil, OBJC_ASSOCIATION_COPY_NONATOMIC);
        }
        return;
    }

    self.state = WFSSAPAssetsStateExtracting;
    self.statusMessage = @"Extracting SAP assets…";
    self.progress = 0.95;

    NSData *pkgData = [_downloadBuffer copy];
    _downloadBuffer = nil;

    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *extractError = nil;
        BOOL ok = [weakSelf extractAssetsFromPackage:pkgData error:&extractError];
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            void (^completion)(BOOL, NSError *) = objc_getAssociatedObject(self, "completionBlock");
            if (completion) {
                if (ok) {
                    self.state = WFSSAPAssetsStateReady;
                    self.progress = 1.0;
                    self.statusMessage = @"SAP assets ready.";
                    completion(YES, nil);
                } else {
                    self.state = WFSSAPAssetsStateFailed;
                    self.statusMessage = extractError.localizedDescription;
                    completion(NO, extractError);
                }
                objc_setAssociatedObject(self, "completionBlock", nil, OBJC_ASSOCIATION_COPY_NONATOMIC);
            }
        });
    });
}

#pragma mark - XAR + CPIO Extraction

- (BOOL)extractAssetsFromPackage:(NSData *)pkgData error:(NSError **)error {
    const uint8_t *bytes = pkgData.bytes;
    NSUInteger length = pkgData.length;

    if (length < 28) {
        if (error) *error = [self err:@"Package too small"];
        return NO;
    }

    uint32_t magic = *(const uint32_t *)bytes;
    if (magic != 0x78617221) {
        if (error) *error = [self err:@"Not a xar archive"];
        return NO;
    }

    uint16_t headerSize = CFSwapInt16BigToHost(*(const uint16_t *)(bytes + 4));
    uint64_t tocCompressedSize = CFSwapInt64BigToHost(*(const uint64_t *)(bytes + 8));
    uint64_t tocUncompressedSize = CFSwapInt64BigToHost(*(const uint64_t *)(bytes + 16));

    if (headerSize + tocCompressedSize > length) {
        if (error) *error = [self err:@"TOC exceeds package size"];
        return NO;
    }

    const void *tocCompressed = bytes + headerSize;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = (Bytef *)tocCompressed;
    strm.avail_in = (uInt)tocCompressedSize;

    NSMutableData *tocData = [NSMutableData dataWithLength:tocUncompressedSize];
    strm.next_out = tocData.mutableBytes;
    strm.avail_out = (uInt)tocUncompressedSize;

    int ret = inflateInit(&strm);
    if (ret != Z_OK) {
        if (error) *error = [self err:@"Failed to init zlib"];
        return NO;
    }
    ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        if (error) *error = [self err:@"Failed to decompress TOC"];
        return NO;
    }
    tocData.length = tocUncompressedSize - strm.avail_out;

    int64_t payloadOffset = -1;
    int64_t payloadSize = -1;

    WFSTOCXMLParserDelegate *tocDelegate = [[WFSTOCXMLParserDelegate alloc] init];
    tocDelegate.headerSize = headerSize;
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:tocData];
    parser.delegate = tocDelegate;
    [parser parse];

    payloadOffset = tocDelegate.payloadOffset;
    payloadSize = tocDelegate.payloadSize;

    if (payloadOffset < 0 || payloadSize < 0) {
        if (error) *error = [self err:@"Payload not found in package"];
        return NO;
    }

    if (payloadOffset + payloadSize > (int64_t)length) {
        if (error) *error = [self err:@"Payload offset exceeds package"];
        return NO;
    }

    if (payloadOffset + kWFSPayloadBZOffset + 4 > (int64_t)length) {
        if (error) *error = [self err:@"BZ2 offset exceeds package"];
        return NO;
    }

    const uint8_t *bzData = bytes + payloadOffset + kWFSPayloadBZOffset;
    NSUInteger bzLength = (NSUInteger)(payloadSize - kWFSPayloadBZOffset);

    bz_stream bzStrm;
    memset(&bzStrm, 0, sizeof(bzStrm));
    bzStrm.next_in = (char *)bzData;
    bzStrm.avail_in = (int)MIN(bzLength, (NSUInteger)INT_MAX);

    NSMutableData *decompressed = [NSMutableData dataWithCapacity:64 << 20];
    char outBuf[65536];

    int bzRet = BZ2_bzDecompressInit(&bzStrm, 0, 0);
    if (bzRet != BZ_OK) {
        if (error) *error = [self err:@"Failed to init bzip2"];
        return NO;
    }

    while (bzRet == BZ_OK) {
        bzStrm.next_out = outBuf;
        bzStrm.avail_out = sizeof(outBuf);
        bzRet = BZ2_bzDecompress(&bzStrm);
        int written = sizeof(outBuf) - bzStrm.avail_out;
        if (written > 0) {
            [decompressed appendBytes:outBuf length:written];
        }
        if (self.cancelled) {
            BZ2_bzDecompressEnd(&bzStrm);
            if (error) *error = [self err:@"Cancelled"];
            return NO;
        }
    }
    BZ2_bzDecompressEnd(&bzStrm);

    if (bzRet != BZ_STREAM_END) {
        if (error) *error = [self err:@"bzip2 decompression failed"];
        return NO;
    }

    if (decompressed.length <= kWFSCPIOOffset) {
        if (error) *error = [self err:@"Decompressed data too small for cpio"];
        return NO;
    }

    const uint8_t *cpioBytes = decompressed.bytes + kWFSCPIOOffset;
    NSUInteger cpioLength = decompressed.length - (NSUInteger)kWFSCPIOOffset;

    NSDictionary<NSString *, NSData *> *files = [self extractCPIOFiles:cpioBytes length:cpioLength error:error];
    if (!files) return NO;

    NSString *dir = [self assetsDirectory];

    NSDictionary<NSString *, NSString *> *nameToPath = @{
        @"CoreFP": kWFSCoreFPPath,
        @"CommerceCore": kWFSCommerceCorePath,
        @"CommerceKit": kWFSCommerceKitPath,
        @"CoreFP_icxs": kWFSCoreFPIXXSPath,
    };

    for (NSString *name in nameToPath) {
        NSString *archivePath = nameToPath[name];
        NSData *data = files[archivePath];
        if (!data.length) {
            if (error) *error = [self err:[NSString stringWithFormat:@"%@ not found in archive", name]];
            return NO;
        }
        NSString *outPath = [dir stringByAppendingPathComponent:[name stringByAppendingPathExtension:@"bin"]];
        if (![data writeToFile:outPath atomically:YES]) {
            if (error) *error = [self err:[NSString stringWithFormat:@"Failed to write %@", name]];
            return NO;
        }
    }

    return YES;
}

- (nullable NSDictionary<NSString *, NSData *> *)extractCPIOFiles:(const uint8_t *)bytes
                                                          length:(NSUInteger)length
                                                           error:(NSError **)error
{
    NSMutableDictionary<NSString *, NSData *> *result = [NSMutableDictionary dictionary];
    NSArray *wantedPaths = @[kWFSCoreFPPath, kWFSCommerceCorePath, kWFSCommerceKitPath, kWFSCoreFPIXXSPath];

    NSMutableSet *wanted = [NSMutableSet setWithArray:wantedPaths];
    NSUInteger offset = 0;

    while (offset + 110 <= length && wanted.count > 0) {
        const char *magic = (const char *)(bytes + offset);
        if (strncmp(magic, "070702", 6) != 0 && strncmp(magic, "070701", 6) != 0) {
            break;
        }

        char hexFilesize[9] = {0};
        memcpy(hexFilesize, bytes + offset + 48, 8);
        uint32_t dataFileSize = (uint32_t)strtoul(hexFilesize, NULL, 16);

        char hexNamesize[9] = {0};
        memcpy(hexNamesize, bytes + offset + 94, 8);
        uint32_t nameSize = (uint32_t)strtoul(hexNamesize, NULL, 16);

        uint32_t headerLen = 110;
        uint32_t alignedHeader = (headerLen + nameSize + 3) & ~3;
        uint32_t alignedData = (dataFileSize + 3) & ~3;

        if (offset + alignedHeader + alignedData > length) break;

        uint32_t nameLen = nameSize > 0 ? nameSize - 1 : 0;
        if (nameLen > 0 && nameLen < 512) {
            NSString *name = [[NSString alloc] initWithBytes:bytes + offset + headerLen length:nameLen encoding:NSUTF8StringEncoding];
            for (NSString *wantedPath in [wanted allObjects]) {
                if ([name isEqualToString:wantedPath]) {
                    const uint8_t *fileData = bytes + offset + alignedHeader;
                    result[name] = [NSData dataWithBytes:fileData length:dataFileSize];
                    [wanted removeObject:wantedPath];
                    break;
                }
            }
        }

        offset += alignedHeader + alignedData;
    }

    return result;
}

#pragma mark - Helpers

- (NSString *)formatBytesPerSecond:(double)bps {
    if (bps <= 0) return @"…";
    if (bps < 1024) return [NSString stringWithFormat:@"%.0f B/s", bps];
    if (bps < 1024 * 1024) return [NSString stringWithFormat:@"%.1f KB/s", bps / 1024.0];
    return [NSString stringWithFormat:@"%.2f MB/s", bps / (1024.0 * 1024.0)];
}

- (NSString *)formatDuration:(double)seconds {
    if (seconds < 0) return @"…";
    if (seconds < 60) return [NSString stringWithFormat:@"%.0fs", seconds];
    int min = (int)seconds / 60;
    int sec = (int)seconds % 60;
    return [NSString stringWithFormat:@"%dm %ds", min, sec];
}

- (NSError *)err:(NSString *)msg {
    return [NSError errorWithDomain:@"WFSSAPAssetsManager" code:-1 userInfo:@{NSLocalizedDescriptionKey: msg}];
}

@end
