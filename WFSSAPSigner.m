#import "WFSSAPSigner.h"
#import "WFSSAPMachine.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

NSString *const WFSSAPSignerErrorDomain = @"WFSSAPSignerErrorDomain";

static NSString *const kWFSSAPCertificateKey = @"sign-sap-setup-cert";
static NSString *const kWFSSAPBufferKey = @"sign-sap-setup-buffer";
static NSString *const kWFSSAPUserAgent = @"Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";
static const uint32_t kWFSSAPSupportedVersion = 200;
static const NSUInteger kWFSSAPMaxHardwareIDLength = 20;
static const NSTimeInterval kWFSSAPRequestTimeout = 30.0;

@implementation WFSSAPConfig
@end

@interface WFSSAPSigner ()
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) WFSSAPMachine *machine;
@property (nonatomic, copy) NSString *setupURL;
@property (nonatomic, copy) NSString *certificateURL;
@property (nonatomic, assign) uint32_t version;
@property (nonatomic, strong) NSData *hardwareID;
@property (nonatomic, assign) uint64_t sapContext;
@property (nonatomic, assign) BOOL closed;
@end

@implementation WFSSAPSigner

+ (nullable instancetype)signerWithConfig:(WFSSAPConfig *)config
                                    error:(NSError **)error
{
    return [[self alloc] initWithConfig:config error:error];
}

+ (nullable NSData *)hardwareIDFromGUID:(NSString *)guid
{
    if (guid.length == 0)
    {
        return nil;
    }

    NSData *guidData = [guid dataUsingEncoding:NSUTF8StringEncoding];
    if (!guidData.length)
    {
        return nil;
    }

    NSUInteger maxLen = kWFSSAPMaxHardwareIDLength;
    NSUInteger len = MIN(guidData.length, maxLen);
    NSMutableData *hardwareID = [NSMutableData dataWithLength:len];
    [hardwareID replaceBytesInRange:NSMakeRange(0, len) withBytes:guidData.bytes];

    return hardwareID;
}

- (nullable instancetype)initWithConfig:(WFSSAPConfig *)config
                                  error:(NSError **)error
{
    self = [super init];
    if (!self)
        return nil;

    if (![self validateConfig:config])
    {
        if (error)
        {
            *error = [NSError errorWithDomain:WFSSAPSignerErrorDomain
                                         code:WFSSAPSignerErrorInvalidConfig
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid SAP configuration."}];
        }
        return nil;
    }

    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
    sessionConfig.timeoutIntervalForRequest = kWFSSAPRequestTimeout;
    _session = [NSURLSession sessionWithConfiguration:sessionConfig];

    _setupURL = [config.setupURL copy];
    _certificateURL = [config.certificateURL copy];
    _version = config.version;
    _hardwareID = [config.hardwareID copy];
    _closed = NO;

    NSError *setupError = nil;
    if (![self performSetupWithError:&setupError])
    {
        if (error)
        {
            *error = setupError;
        }
        return nil;
    }

    return self;
}

#pragma mark - Config Validation

- (BOOL)validateConfig:(WFSSAPConfig *)config
{
    if (config.version != kWFSSAPSupportedVersion)
        return NO;
    if (config.hardwareID.length == 0 || config.hardwareID.length > kWFSSAPMaxHardwareIDLength)
        return NO;
    if (![self validateEndpoint:config.setupURL])
        return NO;
    if (![self validateEndpoint:config.certificateURL])
        return NO;
    return YES;
}

- (BOOL)validateEndpoint:(NSString *)endpoint
{
    if (endpoint.length == 0) return NO;
    NSURL *url = [NSURL URLWithString:endpoint];
    if (!url) return NO;
    if (![url.scheme isEqualToString:@"https"]) return NO;
    if (url.host.length == 0) return NO;
    if (url.user != nil) return NO;
    return YES;
}

#pragma mark - Asset Loading

- (nullable NSData *)loadAsset:(NSString *)name error:(NSError **)error
{
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:name ofType:@"bin"];
    if (!bundlePath)
    {
        bundlePath = [[NSBundle mainBundle] pathForResource:name ofType:nil];
    }

    if (!bundlePath)
    {
        NSString *docDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        bundlePath = [docDir stringByAppendingPathComponent:[NSString stringWithFormat:@"sap_%@.bin", name]];
    }

    if (!bundlePath || ![[NSFileManager defaultManager] fileExistsAtPath:bundlePath])
    {
        if (error)
        {
            *error = [self errorWithCode:WFSSAPSignerErrorSetupFailed
                                 message:[NSString stringWithFormat:@"SAP asset %@ not found. Download SAP assets first.", name]];
        }
        return nil;
    }

    NSData *data = [NSData dataWithContentsOfFile:bundlePath];
    if (!data.length)
    {
        if (error)
        {
            *error = [self errorWithCode:WFSSAPSignerErrorSetupFailed
                                 message:[NSString stringWithFormat:@"Failed to read SAP asset %@.", name]];
        }
        return nil;
    }

    return data;
}

#pragma mark - Setup Protocol

- (BOOL)performSetupWithError:(NSError **)error
{
    NSMutableArray *diagnostics = [NSMutableArray array];
    [diagnostics addObject:@"SAP: loading assets"];

    NSData *coreFPData = [self loadAsset:@"CoreFP" error:error];
    if (!coreFPData)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: CoreFP loaded (%lu bytes)", (unsigned long)coreFPData.length]];

    NSData *commerceCoreData = [self loadAsset:@"CommerceCore" error:error];
    if (!commerceCoreData)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: CommerceCore loaded (%lu bytes)", (unsigned long)commerceCoreData.length]];

    NSData *commerceKitData = [self loadAsset:@"CommerceKit" error:error];
    if (!commerceKitData)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: CommerceKit loaded (%lu bytes)", (unsigned long)commerceKitData.length]];

    NSData *coreFPICXSData = [self loadAsset:@"CoreFP_icxs" error:error];
    if (!coreFPICXSData)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: CoreFP.icxs loaded (%lu bytes)", (unsigned long)coreFPICXSData.length]];

    [diagnostics addObject:@"SAP: opening machine"];
    NSError *machineError = nil;
    WFSSAPMachine *machine = [WFSSAPMachine openWithCoreFP:coreFPData
                                              commerceCore:commerceCoreData
                                              commerceKit:commerceKitData
                                                coreFPICXS:coreFPICXSData
                                                     error:&machineError];
    if (!machine)
    {
        [diagnostics addObject:[NSString stringWithFormat:@"SAP: machine open failed: %@", machineError.localizedDescription ?: @"?"]];
        [self writeSAPDiagnostics:diagnostics];
        if (error)
        {
            *error = machineError;
        }
        return NO;
    }
    _machine = machine;
    [diagnostics addObject:@"SAP: machine opened"];

    [diagnostics addObject:@"SAP: fetching certificate"];
    NSData *certificate = [self fetchCertificateWithError:error];
    if (!certificate)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: certificate fetched (%lu bytes)", (unsigned long)certificate.length]];

    [diagnostics addObject:@"SAP: initializing"];
    NSNumber *contextValue = [_machine initializeWithHardwareID:self.hardwareID error:error];
    if (!contextValue)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }
    _sapContext = contextValue.unsignedLongLongValue;
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: initialized, context=0x%llx", _sapContext]];

    [diagnostics addObject:@"SAP: exchanging setup message"];
    NSDictionary *exchangeResult = [_machine exchangeWithVersion:self.version
                                                     hardwareID:self.hardwareID
                                                        context:_sapContext
                                                          input:certificate
                                                          error:error];
    if (!exchangeResult)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }

    NSData *setupRequest = exchangeResult[@"output"];
    NSNumber *state = exchangeResult[@"state"];
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: exchange state=%@, request=%lu bytes", state, (unsigned long)setupRequest.length]];

    if ([state intValue] != 1)
    {
        NSString *msg = [NSString stringWithFormat:@"SAP setup entered unexpected state %d", [state intValue]];
        [diagnostics addObject:msg];
        [self writeSAPDiagnostics:diagnostics];
        if (error)
        {
            *error = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:msg];
        }
        return NO;
    }

    [diagnostics addObject:@"SAP: exchanging with Apple"];
    NSData *setupReply = [self exchangeSetupMessage:setupRequest error:error];
    if (!setupReply)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: reply received (%lu bytes)", (unsigned long)setupReply.length]];

    NSDictionary *finalResult = [_machine exchangeWithVersion:self.version
                                                  hardwareID:self.hardwareID
                                                     context:_sapContext
                                                       input:setupReply
                                                       error:error];
    if (!finalResult)
    {
        [self writeSAPDiagnostics:diagnostics];
        return NO;
    }

    NSNumber *finalState = finalResult[@"state"];
    [diagnostics addObject:[NSString stringWithFormat:@"SAP: final state=%@", finalState]];

    if ([finalState intValue] != 0)
    {
        NSString *msg = [NSString stringWithFormat:@"SAP setup completed in unexpected state %d", [finalState intValue]];
        [diagnostics addObject:msg];
        [self writeSAPDiagnostics:diagnostics];
        if (error)
        {
            *error = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:msg];
        }
        return NO;
    }

    [diagnostics addObject:@"SAP: setup complete"];
    [self writeSAPDiagnostics:diagnostics];
    return YES;
}

- (nullable NSData *)fetchCertificateWithError:(NSError **)error
{
    NSURL *url = [NSURL URLWithString:self.certificateURL];
    if (!url)
    {
        if (error) *error = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:@"Invalid SAP certificate URL."];
        return nil;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"GET";
    [request setValue:kWFSSAPUserAgent forHTTPHeaderField:@"User-Agent"];
    [request setTimeoutInterval:kWFSSAPRequestTimeout];

    __block NSData *resultData = nil;
    __block NSError *resultError = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *networkError) {
        if (networkError)
        {
            resultError = networkError;
            dispatch_semaphore_signal(semaphore);
            return;
        }

        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        if (httpResponse.statusCode != 200)
        {
            resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed
                                     message:[NSString stringWithFormat:@"SAP certificate request returned HTTP %ld.", (long)httpResponse.statusCode]];
            dispatch_semaphore_signal(semaphore);
            return;
        }

        NSDictionary *plist = [self parsePlistResponse:data];
        if (!plist)
        {
            resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:@"Failed to parse SAP certificate response."];
            dispatch_semaphore_signal(semaphore);
            return;
        }

        NSData *certData = plist[kWFSSAPCertificateKey];
        if (![certData isKindOfClass:[NSData class]] || certData.length == 0)
        {
            resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:@"SAP certificate response missing certificate data."];
            dispatch_semaphore_signal(semaphore);
            return;
        }

        resultData = certData;
        dispatch_semaphore_signal(semaphore);
    }] resume];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (error) *error = resultError;
    return resultData;
}

- (nullable NSData *)exchangeSetupMessage:(NSData *)message error:(NSError **)error
{
    NSURL *url = [NSURL URLWithString:self.setupURL];
    if (!url)
    {
        if (error) *error = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:@"Invalid SAP setup URL."];
        return nil;
    }

    NSDictionary *envelope = @{kWFSSAPBufferKey: message};
    NSError *plistError = nil;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:envelope
                                                                  format:NSPropertyListXMLFormat_v1_0
                                                                 options:0
                                                                   error:&plistError];
    if (!plistData)
    {
        if (error) *error = plistError;
        return nil;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/x-plist" forHTTPHeaderField:@"Content-Type"];
    [request setValue:kWFSSAPUserAgent forHTTPHeaderField:@"User-Agent"];
    [request setTimeoutInterval:kWFSSAPRequestTimeout];
    request.HTTPBody = plistData;

    __block NSData *resultData = nil;
    __block NSError *resultError = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *networkError) {
        if (networkError)
        {
            resultError = networkError;
            dispatch_semaphore_signal(semaphore);
            return;
        }

        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        if (httpResponse.statusCode != 200)
        {
            resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed
                                     message:[NSString stringWithFormat:@"SAP setup exchange returned HTTP %ld.", (long)httpResponse.statusCode]];
            dispatch_semaphore_signal(semaphore);
            return;
        }

        NSDictionary *plist = [self parsePlistResponse:data];
        if (!plist)
        {
            resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:@"Failed to parse SAP setup response."];
            dispatch_semaphore_signal(semaphore);
            return;
        }

        NSData *replyData = plist[kWFSSAPBufferKey];
        if (![replyData isKindOfClass:[NSData class]] || replyData.length == 0)
        {
            resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed message:@"SAP setup response missing buffer data."];
            dispatch_semaphore_signal(semaphore);
            return;
        }

        resultData = replyData;
        dispatch_semaphore_signal(semaphore);
    }] resume];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (error) *error = resultError;
    return resultData;
}

#pragma mark - ActionSigner

- (nullable NSData *)sign:(NSData *)input error:(NSError **)error
{
    if (self.closed)
    {
        if (error)
        {
            *error = [self errorWithCode:WFSSAPSignerErrorClosed message:@"SAP signer is closed."];
        }
        return nil;
    }

    if (input.length == 0)
    {
        if (error)
        {
            *error = [self errorWithCode:WFSSAPSignerErrorSigningFailed message:@"Cannot sign empty input."];
        }
        return nil;
    }

    if (!_machine || _sapContext == 0)
    {
        if (error)
        {
            *error = [self errorWithCode:WFSSAPSignerErrorSigningFailed message:@"SAP machine not initialized."];
        }
        return nil;
    }

    NSMutableArray *diagnostics = [NSMutableArray array];
    [diagnostics addObject:[NSString stringWithFormat:@"SAP Sign: signing %lu bytes", (unsigned long)input.length]];

    NSError *signError = nil;
    NSData *signature = [_machine signWithContext:_sapContext input:input error:&signError];

    if (signature.length)
    {
        [diagnostics addObject:[NSString stringWithFormat:@"SAP Sign: signature generated (%lu bytes)", (unsigned long)signature.length]];
    }
    else
    {
        [diagnostics addObject:[NSString stringWithFormat:@"SAP Sign: signing failed: %@", signError.localizedDescription ?: @"?"]];
    }

    [self writeSAPDiagnostics:diagnostics];

    if (!signature.length)
    {
        if (error) *error = signError ?: [self errorWithCode:WFSSAPSignerErrorSigningFailed message:@"Signing returned empty result."];
        return nil;
    }

    return signature;
}

- (void)close
{
    if (self.closed) return;
    self.closed = YES;

    if (_machine && _sapContext)
    {
        [_machine teardownWithContext:_sapContext error:nil];
    }

    [_machine close];
    _machine = nil;

    [self.session invalidateAndCancel];
}

- (void)dealloc
{
    [self close];
}

#pragma mark - Helpers

- (NSDictionary *)parsePlistResponse:(NSData *)data
{
    if (data.length == 0) return nil;

    NSError *error = nil;
    id obj = [NSPropertyListSerialization propertyListWithData:data
                                                      options:0
                                                       format:NULL
                                                        error:&error];
    if (!error && [obj isKindOfClass:[NSDictionary class]])
    {
        return obj;
    }

    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (text.length == 0) return nil;

    NSRegularExpression *dictRegex = [NSRegularExpression regularExpressionWithPattern:@"<dict\\b[^>]*>.*</dict>"
                                                                              options:NSRegularExpressionDotMatchesLineSeparators
                                                                                error:nil];
    NSTextCheckingResult *match = [dictRegex firstMatchInString:text
                                                       options:0
                                                         range:NSMakeRange(0, text.length)];
    if (!match) return nil;

    NSString *dictXML = [text substringWithRange:match.range];
    NSString *wrapped = [NSString stringWithFormat:
        @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        @"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        @"<plist version=\"1.0\">\n%@\n</plist>", dictXML];

    NSData *wrappedData = [wrapped dataUsingEncoding:NSUTF8StringEncoding];
    id wrappedObj = [NSPropertyListSerialization propertyListWithData:wrappedData
                                                             options:0
                                                              format:NULL
                                                               error:nil];
    return [wrappedObj isKindOfClass:[NSDictionary class]] ? wrappedObj : nil;
}

- (NSError *)errorWithCode:(NSInteger)code message:(NSString *)message
{
    return [NSError errorWithDomain:WFSSAPSignerErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"Unknown SAP error"}];
}

- (void)writeSAPDiagnostics:(NSArray *)diagnostics
{
    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *path = [directory stringByAppendingPathComponent:@"WaffleStore_sap.log"];
    NSMutableString *contents = [NSMutableString stringWithFormat:@"WaffleStore SAP Signer Log - %@\n", [NSDate date]];
    for (NSString *line in diagnostics)
    {
        [contents appendFormat:@"%@\n", line];
    }
    [contents writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

@end
