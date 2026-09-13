#import "WFSSAPSigner.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

NSString *const WFSSAPSignerErrorDomain = @"WFSSAPSignerErrorDomain";

static NSString *const kWFSSAPCertificateKey = @"sign-sap-setup-cert";
static NSString *const kWFSSAPBufferKey = @"sign-sap-setup-buffer";
static NSString *const kWFSSAPUserAgent = @"Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";
static const uint32_t kWFSSAPSupportedVersion = 200;
static const NSUInteger kWFSSAPMaxHardwareIDLength = 20;
static const NSTimeInterval kWFSSAPRequestTimeout = 30.0;
static const int64_t kWFSSAPMaxSetupBody = 1 << 20;

@implementation WFSSAPConfig
@end

@interface WFSSAPSigner ()
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, copy) NSString *setupURL;
@property (nonatomic, copy) NSString *certificateURL;
@property (nonatomic, assign) uint32_t version;
@property (nonatomic, strong) NSData *hardwareID;
@property (nonatomic, assign) BOOL closed;
@end

@implementation WFSSAPSigner

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

	NSUInteger maxLen = 20;
	NSUInteger len = MIN(guidData.length, maxLen);
	NSMutableData *hardwareID = [NSMutableData dataWithLength:len];
	[hardwareID replaceBytesInRange:NSMakeRange(0, len) withBytes:guidData.bytes];

	return hardwareID;
}

+ (nullable instancetype)signerWithConfig:(WFSSAPConfig *)config
                                    error:(NSError **)error
{
	return [[self alloc] initWithConfig:config error:error];
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
	{
		return NO;
	}

	if (config.hardwareID.length == 0 || config.hardwareID.length > kWFSSAPMaxHardwareIDLength)
	{
		return NO;
	}

	if (![self validateEndpoint:config.setupURL])
	{
		return NO;
	}

	if (![self validateEndpoint:config.certificateURL])
	{
		return NO;
	}

	return YES;
}

- (BOOL)validateEndpoint:(NSString *)endpoint
{
	if (endpoint.length == 0)
	{
		return NO;
	}

	NSURL *url = [NSURL URLWithString:endpoint];
	if (!url)
	{
		return NO;
	}

	if (![url.scheme isEqualToString:@"https"])
	{
		return NO;
	}

	if (url.host.length == 0)
	{
		return NO;
	}

	if (url.user != nil)
	{
		return NO;
	}

	return YES;
}

#pragma mark - Setup Protocol

- (BOOL)performSetupWithError:(NSError **)error
{
	NSData *certificate = [self fetchCertificateWithError:error];
	if (!certificate)
	{
		return NO;
	}

	NSData *setupRequest = [self createSetupRequestWithData:certificate error:error];
	if (!setupRequest)
	{
		return NO;
	}

	NSData *setupReply = [self exchangeSetupMessage:setupRequest error:error];
	if (!setupReply)
	{
		return NO;
	}

	return YES;
}

- (nullable NSData *)fetchCertificateWithError:(NSError **)error
{
	NSURL *url = [NSURL URLWithString:self.certificateURL];
	if (!url)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorSetupFailed
								 message:@"Invalid SAP certificate URL."];
		}
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
			resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed
									 message:@"Failed to parse SAP certificate response."];
			dispatch_semaphore_signal(semaphore);
			return;
		}

		NSData *certData = plist[kWFSSAPCertificateKey];
		if (![certData isKindOfClass:[NSData class]] || certData.length == 0)
		{
			resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed
									 message:@"SAP certificate response is missing certificate data."];
			dispatch_semaphore_signal(semaphore);
			return;
		}

		resultData = certData;
		dispatch_semaphore_signal(semaphore);
	}] resume];

	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

	if (error)
	{
		*error = resultError;
	}

	return resultData;
}

- (nullable NSData *)createSetupRequestWithData:(NSData *)certificateData
                                         error:(NSError **)error
{
	NSDictionary *envelope = @{kWFSSAPBufferKey: certificateData};
	NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:envelope
																  format:NSPropertyListXMLFormat_v1_0
																 options:0
																   error:error];
	if (!plistData)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorSetupFailed
								 message:@"Failed to encode SAP setup message."];
		}
		return nil;
	}

	return plistData;
}

- (nullable NSData *)exchangeSetupMessage:(NSData *)message
                                    error:(NSError **)error
{
	NSURL *url = [NSURL URLWithString:self.setupURL];
	if (!url)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorSetupFailed
								 message:@"Invalid SAP setup URL."];
		}
		return nil;
	}

	NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
	request.HTTPMethod = @"POST";
	[request setValue:@"application/x-plist" forHTTPHeaderField:@"Content-Type"];
	[request setValue:kWFSSAPUserAgent forHTTPHeaderField:@"User-Agent"];
	[request setTimeoutInterval:kWFSSAPRequestTimeout];
	request.HTTPBody = message;

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
			resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed
									 message:@"Failed to parse SAP setup response."];
			dispatch_semaphore_signal(semaphore);
			return;
		}

		NSData *replyData = plist[kWFSSAPBufferKey];
		if (![replyData isKindOfClass:[NSData class]] || replyData.length == 0)
		{
			resultError = [self errorWithCode:WFSSAPSignerErrorSetupFailed
									 message:@"SAP setup response is missing buffer data."];
			dispatch_semaphore_signal(semaphore);
			return;
		}

		resultData = replyData;
		dispatch_semaphore_signal(semaphore);
	}] resume];

	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

	if (error)
	{
		*error = resultError;
	}

	return resultData;
}

#pragma mark - ActionSigner

- (nullable NSData *)sign:(NSData *)input error:(NSError **)error
{
	if (self.closed)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorClosed
								 message:@"SAP signer is closed."];
		}
		return nil;
	}

	if (input.length == 0)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorSigningFailed
								 message:@"Cannot sign empty input."];
		}
		return nil;
	}

	NSMutableArray *diagnostics = [NSMutableArray array];
	[diagnostics addObject:@"SAP Sign: generating ActionSignature"];

	NSData *signature = [self performSign:input diagnostics:diagnostics error:error];

	if (signature)
	{
		[diagnostics addObject:[NSString stringWithFormat:@"SAP Sign: signature generated (%lu bytes)", (unsigned long)signature.length]];
	}
	else
	{
		[diagnostics addObject:@"SAP Sign: signing failed"];
	}

	[self writeSAPDiagnostics:diagnostics];

	return signature;
}

- (nullable NSData *)performSign:(NSData *)input
                   diagnostics:(NSMutableArray *)diagnostics
                         error:(NSError **)error
{
	NSData *hwBlock = [self hardwareBlock];
	if (!hwBlock)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorSigningFailed
								 message:@"Failed to create hardware block."];
		}
		return nil;
	}

	NSData *signature = [self signWithHardware:hwBlock input:input diagnostics:diagnostics error:error];

	return signature;
}

- (nullable NSData *)signWithHardware:(NSData *)hardware
                               input:(NSData *)input
                        diagnostics:(NSMutableArray *)diagnostics
                              error:(NSError **)error
{
	NSData *guidData = [self guidFromHardwareID];
	if (!guidData)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorSigningFailed
								 message:@"Failed to derive GUID from hardware ID."];
		}
		return nil;
	}

	[diagnostics addObject:[NSString stringWithFormat:@"SAP hardware ID: %lu bytes", (unsigned long)self.hardwareID.length]];

	NSData *signature = [self computeSignatureForInput:input hardware:hardware diagnostics:diagnostics error:error];

	return signature;
}

- (nullable NSData *)computeSignatureForInput:(NSData *)input
                                     hardware:(NSData *)hardware
                                diagnostics:(NSMutableArray *)diagnostics
                                      error:(NSError **)error
{
	NSMutableData *signData = [NSMutableData data];
	[signData appendData:input];

	unsigned char digest[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(signData.bytes, (CC_LONG)signData.length, digest);

	NSData *hashData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];

	NSData *hmacKey = [self deriveSigningKey];
	if (!hmacKey)
	{
		if (error)
		{
			*error = [self errorWithCode:WFSSAPSignerErrorSigningFailed
								 message:@"Failed to derive signing key."];
		}
		return nil;
	}

	unsigned char mac[CC_SHA256_DIGEST_LENGTH];
	CCHmac(kCCHmacAlgSHA256, hmacKey.bytes, hmacKey.length, hashData.bytes, hashData.length, mac);

	NSData *signature = [NSData dataWithBytes:mac length:CC_SHA256_DIGEST_LENGTH];

	[diagnostics addObject:[NSString stringWithFormat:@"SAP signature computed (%lu bytes)", (unsigned long)signature.length]];

	return signature;
}

- (nullable NSData *)deriveSigningKey
{
	NSMutableData *keyMaterial = [NSMutableData data];
	[keyMaterial appendData:self.hardwareID];

	NSData *versionData = [NSData dataWithBytes:&_version length:sizeof(uint32_t)];
	[keyMaterial appendData:versionData];

	unsigned char digest[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(keyMaterial.bytes, (CC_LONG)keyMaterial.length, digest);

	return [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
}

- (nullable NSData *)guidFromHardwareID
{
	if (self.hardwareID.length == 0)
	{
		return nil;
	}

	unsigned char digest[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(self.hardwareID.bytes, (CC_LONG)self.hardwareID.length, digest);

	NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
	{
		[hex appendFormat:@"%02X", digest[i]];
	}

	NSData *hexData = [hex dataUsingEncoding:NSUTF8StringEncoding];
	return hexData;
}

- (nullable NSData *)hardwareBlock
{
	NSUInteger length = self.hardwareID.length;
	if (length == 0 || length > kWFSSAPMaxHardwareIDLength)
	{
		return nil;
	}

	NSMutableData *block = [NSMutableData dataWithLength:24];
	uint32_t lengthField = (uint32_t)length;
	[block replaceBytesInRange:NSMakeRange(0, 4) withBytes:&lengthField];
	[block replaceBytesInRange:NSMakeRange(4, length) withBytes:self.hardwareID.bytes];

	return block;
}

#pragma mark - Cleanup

- (void)close
{
	if (self.closed)
	{
		return;
	}

	self.closed = YES;
	[self.session invalidateAndCancel];
}

- (void)dealloc
{
	[self close];
}

#pragma mark - Helpers

- (NSDictionary *)parsePlistResponse:(NSData *)data
{
	if (data.length == 0)
	{
		return nil;
	}

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
	if (text.length == 0)
	{
		return nil;
	}

	NSRegularExpression *dictRegex = [NSRegularExpression regularExpressionWithPattern:@"<dict\\b[^>]*>.*</dict>"
																			  options:NSRegularExpressionDotMatchesLineSeparators
																				error:nil];
	NSTextCheckingResult *match = [dictRegex firstMatchInString:text
													   options:0
														 range:NSMakeRange(0, text.length)];
	if (!match)
	{
		return nil;
	}

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
