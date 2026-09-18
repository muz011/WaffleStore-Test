#import "WFSSAPShims.h"
#import "WFSBridgingHeader.h"
#import "WaffleStore-Swift.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <ctype.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/time.h>

static const uint64_t kShimBase     = 0x0000200000000000;
static const uint64_t kShimCodeSize = 0x80000;
static const uint64_t kShimSize     = 0x100000;
static const uint64_t kShimSlotSize = 16;

static const uint64_t kShimHeapBase = 0x0000600000000000;
static const uint64_t kShimHeapSize = 16 << 20;

static const uint64_t kFakeHandle      = 0xFFFFFFFFFFFFFFFFULL;
static const int      kCoreFPFileFd    = 3;
static const NSUInteger kMaxGuestTransfer = 64 << 20;

static BOOL WFSSAPTraceEnabled(void)
{
    static BOOL enabled = NO;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const char *v = getenv("WFS_SAP_TRACE");
        enabled = (v != NULL && strlen(v) > 0 && strcmp(v, "0") != 0);
    });
    return enabled;
}

static NSString *WFSHex(uint64_t v)
{
    return [NSString stringWithFormat:@"0x%llx", v];
}

#pragma mark - Shim Entry

@interface WFSSAPShimEntry : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, assign) SEL handler;
@end

@implementation WFSSAPShimEntry
@end

#pragma mark - Shims

@interface WFSSAPShims () {
    WFSSwiftUnicorn *_unicorn;
    void *_engine;
    uint64_t _codeCursor;
    uint64_t _dataCursor;
    uint64_t _heapCursor;
    NSMutableDictionary<NSNumber *, WFSSAPShimEntry *> *_entries;
    NSMutableDictionary<NSString *, NSNumber *> *_symbols;
    NSDictionary<NSString *, NSNumber *> *_coreExports;

    NSData *_icxs;
    NSUInteger _icxsCursor;
    NSUInteger _iterator;
    uint64_t _errnoAddr;
    uint64_t _stackChkGuardAddr;
    uint64_t _kCFAllocatorDefaultAddr;
    uint64_t _kCFAllocatorNullAddr;
    uint64_t _kDADiskDescriptionVolumeUUIDKeyAddr;
    uint64_t _kIOMasterPortDefaultAddr;
}
@end

@implementation WFSSAPShims

- (nullable instancetype)initWithEngine:(void *)engine
                                     api:(WFSSwiftUnicorn *)api
                            coreExports:(NSDictionary<NSString *, NSNumber *> *)coreExports
                                   icxs:(nullable NSData *)icxs
                                  error:(NSError **)error
{
    self = [super init];
    if (!self) return nil;

    _engine = engine;
    _unicorn = api;
    _codeCursor = kShimBase;
    _dataCursor = kShimBase + kShimCodeSize;
    _heapCursor = kShimHeapBase;
    _entries = [NSMutableDictionary dictionary];
    _symbols = [NSMutableDictionary dictionary];
    _coreExports = [coreExports copy];
    _icxs = [icxs copy] ?: [NSData data];

    if (![_unicorn isLoaded]) {
        if (error) *error = [self shimError:@"Unicorn API not loaded"];
        return nil;
    }

    int rc = [_unicorn memMap:kShimBase size:kShimSize perms:UC_PROT_ALL];
    if (rc != 0) {
        if (error) *error = [self shimError:[NSString stringWithFormat:@"memMap shim area failed: %s", [[_unicorn strerror:rc] UTF8String]]];
        return nil;
    }

    rc = [_unicorn memMap:kShimHeapBase size:kShimHeapSize perms:UC_PROT_ALL];
    if (rc != 0) {
        if (error) *error = [self shimError:[NSString stringWithFormat:@"memMap shim heap failed: %s", [[_unicorn strerror:rc] UTF8String]]];
        return nil;
    }

    if (![self registerMemoryServices:error]) return NO;
    if (![self registerPlatformServices:error]) return NO;

    [self registerDataSymbols];

    return self;
}

#pragma mark - Data Symbols

- (void)registerDataSymbols
{
    _errnoAddr = [self reserveDataBytes:8];
    _stackChkGuardAddr = [self reserveDataBytes:8];
    [self writeGuestUint64:_errnoAddr value:0];

    uint8_t guard[8] = {0xA5, 0x71, 0x3C, 0xD9, 0x86, 0x42, 0xEF, 0x10};
    [_unicorn memWrite:_stackChkGuardAddr data:guard size:8];

    _kCFAllocatorDefaultAddr = [self reserveDataSymbol:@"_kCFAllocatorDefault"];
    _kCFAllocatorNullAddr = [self reserveDataSymbol:@"_kCFAllocatorNull"];
    _kDADiskDescriptionVolumeUUIDKeyAddr = [self reserveDataSymbol:@"_kDADiskDescriptionVolumeUUIDKey"];
    _kIOMasterPortDefaultAddr = [self reserveDataSymbol:@"_kIOMasterPortDefault"];
}

- (uint64_t)reserveDataSymbol:(NSString *)name
{
    uint64_t addr = [self reserveDataBytes:8];
    [self writeGuestUint64:addr value:0];
    _symbols[name] = @(addr);
    return addr;
}

- (uint64_t)reserveDataBytes:(uint64_t)size
{
    uint64_t aligned = (size + 15) & ~15ULL;
    uint64_t addr = _dataCursor;
    _dataCursor += aligned;
    return addr;
}

#pragma mark - Memory Services

- (BOOL)registerMemoryServices:(NSError **)error
{
    [self addFunction:@"_malloc" handler:@selector(shim_malloc)];
    [self addFunction:@"_malloc_good_size" handler:@selector(shim_malloc_good_size)];
    [self addFunction:@"_malloc_size" handler:@selector(shim_malloc_size)];
    [self addFunction:@"_calloc" handler:@selector(shim_calloc)];
    [self addFunction:@"_realloc" handler:@selector(shim_realloc)];
    [self addFunction:@"_reallocf" handler:@selector(shim_realloc)];
    [self addFunction:@"_free" handler:@selector(shim_free)];
    [self addFunction:@"_memcpy" handler:@selector(shim_memcpy)];
    [self addFunction:@"_memmove" handler:@selector(shim_memmove)];
    [self addFunction:@"_memset" handler:@selector(shim_memset)];
    [self addFunction:@"___bzero" handler:@selector(shim_bzero)];
    [self addFunction:@"___memcpy_chk" handler:@selector(shim_memcpy_chk)];
    [self addFunction:@"___memset_chk" handler:@selector(shim_memset_chk)];
    [self addFunction:@"_memcmp" handler:@selector(shim_memcmp)];
    [self addFunction:@"_strlen" handler:@selector(shim_strlen)];
    [self addFunction:@"_strcmp" handler:@selector(shim_strcmp)];
    [self addFunction:@"_strncmp" handler:@selector(shim_strncmp)];
    [self addFunction:@"_strcpy" handler:@selector(shim_strcpy)];
    [self addFunction:@"_strncpy" handler:@selector(shim_strncpy)];
    [self addFunction:@"_strdup" handler:@selector(shim_strdup)];
    [self addFunction:@"_strerror" handler:@selector(shim_strerror)];
    [self addFunction:@"_snprintf" handler:@selector(shim_snprintf)];
    [self addFunction:@"_sprintf" handler:@selector(shim_sprintf)];
    [self addFunction:@"_atoi" handler:@selector(shim_atoi)];
    [self addFunction:@"_atol" handler:@selector(shim_atol)];
    [self addFunction:@"_strtoul" handler:@selector(shim_strtoul)];
    [self addFunction:@"_strtoull" handler:@selector(shim_strtoull)];
    return YES;
}

#pragma mark - Platform Services

- (BOOL)registerPlatformServices:(NSError **)error
{
    [self addFunction:@"_open" handler:@selector(shim_open)];
    [self addFunction:@"_open$UNIX2003" handler:@selector(shim_open)];
    [self addFunction:@"_read" handler:@selector(shim_read)];
    [self addFunction:@"_read$UNIX2003" handler:@selector(shim_read)];
    [self addFunction:@"_close" handler:@selector(shim_close)];
    [self addFunction:@"_close$UNIX2003" handler:@selector(shim_close)];

    [self addFunction:@"_gettimeofday" handler:@selector(shim_gettimeofday)];
    [self addFunction:@"_sysctlbyname" handler:@selector(shim_sysctlbyname)];
    [self addFunction:@"_pthread_once" handler:@selector(shim_pthread_once)];
    [self addFunction:@"_pthread_mutex_lock" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_mutex_unlock" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_mutex_init" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_mutex_destroy" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_rwlock_init" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_rwlock_destroy" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_rwlock_rdlock" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_rwlock_rdlock$UNIX2003" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_rwlock_unlock" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_rwlock_wrlock" handler:@selector(shim_zero)];
    [self addFunction:@"_pthread_self" handler:@selector(shim_zero)];
    [self addFunction:@"_OSAtomicCompareAndSwap32Barrier" handler:@selector(shim_OSAtomicCompareAndSwap32Barrier)];
    [self addFunction:@"___error" handler:@selector(shim_error)];
    [self addFunction:@"_getenv" handler:@selector(shim_zero)];
    [self addFunction:@"_arc4random" handler:@selector(shim_arc4random)];

    [self addFunction:@"_dlopen" handler:@selector(shim_dlopen)];
    [self addFunction:@"_dlsym" handler:@selector(shim_dlsym)];
    [self addFunction:@"_objc_msgSend" handler:@selector(shim_objc_msgSend)];

    [self addFunction:@"_abort" handler:@selector(shim_abort)];
    [self addFunction:@"___stack_chk_fail" handler:@selector(shim_abort)];
    [self addFunction:@"_dyld_stub_binder" handler:@selector(shim_abort)];

    [self addFunction:@"_IOServiceMatching" handler:@selector(shim_zero)];
    [self addFunction:@"_IOServiceGetMatchingService" handler:@selector(shim_ioServiceGetMatchingService)];
    [self addFunction:@"_IOServiceGetMatchingServices" handler:@selector(shim_ioServiceGetMatchingServices)];
    [self addFunction:@"_IORegistryEntryCreateCFProperty" handler:@selector(shim_fake)];
    [self addFunction:@"_IORegistryEntryGetParentEntry" handler:@selector(shim_ioRegistryEntryGetParentEntry)];
    [self addFunction:@"_IORegistryEntryFromPath" handler:@selector(shim_zero)];
    [self addFunction:@"_IORegistryEntrySearchCFProperty" handler:@selector(shim_zero)];
    [self addFunction:@"_IOIteratorNext" handler:@selector(shim_ioIteratorNext)];
    [self addFunction:@"_IOObjectConformsTo" handler:@selector(shim_zero)];
    [self addFunction:@"_IOObjectRelease" handler:@selector(shim_zero)];
    [self addFunction:@"_IOServiceOpen" handler:@selector(shim_ioServiceOpen)];
    [self addFunction:@"_IOServiceClose" handler:@selector(shim_zero)];
    [self addFunction:@"_IOConnectCallMethod" handler:@selector(shim_ioConnectCallMethod)];
    [self addFunction:@"_IOCFSerialize" handler:@selector(shim_zero)];

    [self addFunction:@"_CFDictionaryGetValue" handler:@selector(shim_fake)];
    [self addFunction:@"_DADiskCopyDescription" handler:@selector(shim_fake)];
    [self addFunction:@"_DADiskCreateFromBSDName" handler:@selector(shim_fake)];
    [self addFunction:@"_DASessionCreate" handler:@selector(shim_fake)];
    [self addFunction:@"_CFStringCreateWithCString" handler:@selector(shim_cfStringCreateWithCString)];
    [self addFunction:@"_CFStringCreateWithCStringNoCopy" handler:@selector(shim_zero)];
    [self addFunction:@"_CFStringGetCString" handler:@selector(shim_cfStringGetCString)];
    [self addFunction:@"_CFStringGetLength" handler:@selector(shim_zero)];
    [self addFunction:@"_CFStringGetMaximumSizeForEncoding" handler:@selector(shim_zero)];
    [self addFunction:@"_CFDataSetTypes" handler:@selector(shim_zero)];
    [self addFunction:@"_CFDataGetBytePtr" handler:@selector(shim_zero)];
    [self addFunction:@"_CFDataGetLength" handler:@selector(shim_zero)];
    [self addFunction:@"_CFBundleGetMainBundle" handler:@selector(shim_zero)];
    [self addFunction:@"_CFUUIDCreateString" handler:@selector(shim_zero)];
    [self addFunction:@"_CFRelease" handler:@selector(shim_zero)];

    [self addFunction:@"_fcntl" handler:@selector(shim_minusone)];
    [self addFunction:@"_fcntl$UNIX2003" handler:@selector(shim_minusone)];
    [self addFunction:@"_lstat$INODE64" handler:@selector(shim_minusone)];
    [self addFunction:@"_statfs" handler:@selector(shim_minusone)];
    [self addFunction:@"_statfs$INODE64" handler:@selector(shim_minusone)];
    [self addFunction:@"_sysctl" handler:@selector(shim_minusone)];

    [self addFunction:@"_SecRandomCopyBytes" handler:@selector(shim_SecRandomCopyBytes)];
    [self addFunction:@"_SecKeyCreateSignature" handler:@selector(shim_unsupported)];
    [self addFunction:@"_SecKeyCreateRandomKey" handler:@selector(shim_unsupported)];
    [self addFunction:@"_SecKeyCopyPublicKey" handler:@selector(shim_unsupported)];
    [self addFunction:@"_SecKeyCopyExternalRepresentation" handler:@selector(shim_unsupported)];
    [self addFunction:@"_SecKeyCopyAttributes" handler:@selector(shim_unsupported)];

    [self addFunction:@"_CC_SHA1" handler:@selector(shim_CC_SHA1)];
    [self addFunction:@"_CC_SHA256" handler:@selector(shim_CC_SHA256)];
    [self addFunction:@"_CC_MD5" handler:@selector(shim_CC_MD5)];
    [self addFunction:@"_CCHmac" handler:@selector(shim_CCHmac)];

    return YES;
}

#pragma mark - Symbol Resolution

- (uint64_t)resolveSymbol:(NSString *)name error:(NSError **)error
{
    NSNumber *existing = _symbols[name];
    if (existing) return existing.unsignedLongLongValue;

    uint64_t newAddr = [self addFunction:name handler:@selector(shim_unsupported)];
    if (newAddr == 0) {
        if (error) *error = [self shimError:[NSString stringWithFormat:@"shim area full resolving %@", name]];
        return 0;
    }
    return newAddr;
}

#pragma mark - Function Registration

- (uint64_t)addFunction:(NSString *)name handler:(SEL)handler
{
    NSNumber *existing = _symbols[name];
    if (existing) return existing.unsignedLongLongValue;

    if (_codeCursor + kShimSlotSize > kShimBase + kShimCodeSize) return 0;

    uint64_t addr = _codeCursor;
    _codeCursor += kShimSlotSize;

    uint8_t ret = 0xC3;
    [_unicorn memWrite:addr data:&ret size:1];

    WFSSAPShimEntry *entry = [WFSSAPShimEntry new];
    entry.name = name;
    entry.handler = handler;
    _entries[@(addr)] = entry;
    _symbols[name] = @(addr);

    return addr;
}

#pragma mark - Dispatch

- (void)dispatchAtAddress:(uint64_t)address
{
    if (address < kShimBase || address >= kShimBase + kShimCodeSize) {
        [self fail:[NSString stringWithFormat:@"dispatch outside shim code range %#llx", address]];
        return;
    }

    WFSSAPShimEntry *entry = _entries[@(address)];
    if (!entry) {
        return;
    }

    if (entry.handler == @selector(shim_unsupported)) {
        [self fail:[NSString stringWithFormat:@"guest called unsupported import %@", entry.name]];
        return;
    }

    if (WFSSAPTraceEnabled()) {
        NSLog(@"[WFS-SAP] shim=%@ RIP=%@ RDI=%@ RSI=%@ RDX=%@ RCX=%@ R8=%@ R9=%@",
              entry.name,
              WFSHex([_unicorn regReadU64:UC_X86_REG_RIP]),
              WFSHex([self argumentAtIndex:0]),
              WFSHex([self argumentAtIndex:1]),
              WFSHex([self argumentAtIndex:2]),
              WFSHex([self argumentAtIndex:3]),
              WFSHex([self argumentAtIndex:4]),
              WFSHex([self argumentAtIndex:5]));
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    if ([self respondsToSelector:entry.handler]) {
        [self performSelector:entry.handler];
    } else {
        [self fail:[NSString stringWithFormat:@"shim handler not found for %@", entry.name]];
    }
#pragma clang diagnostic pop

    if (WFSSAPTraceEnabled()) {
        NSLog(@"[WFS-SAP] shim=%@ return=%@", entry.name, WFSHex([_unicorn regReadU64:UC_X86_REG_RAX]));
    }
}

- (void)fail:(NSString *)message
{
    if (_faulted) return;
    _fault = [NSError errorWithDomain:@"WFSSAPShims" code:-1
                             userInfo:@{NSLocalizedDescriptionKey: message}];
    [_unicorn emuStop];
}

- (void)resetFault
{
    _fault = nil;
}

#pragma mark - Register/Argument Helpers

- (uint64_t)argumentAtIndex:(int)index
{
    static const int regs[] = {
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
        UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9
    };
    if (index >= 0 && index < 6) {
        return [_unicorn regReadU64:regs[index]];
    }
    uint64_t rsp = [_unicorn regReadU64:UC_X86_REG_RSP];
    uint64_t val = 0;
    [_unicorn memRead:(rsp + 8 + (index - 6) * 8) buffer:&val size:8];
    return val;
}

- (void)setResult:(uint64_t)value
{
    [_unicorn regWriteU64:UC_X86_REG_RAX :value];
}

- (uint64_t)readGuestUint64:(uint64_t)addr
{
    uint64_t v = 0;
    if (addr == 0) return 0;
    [_unicorn memRead:addr buffer:&v size:8];
    return v;
}

- (uint32_t)readGuestUint32:(uint64_t)addr
{
    uint32_t v = 0;
    if (addr == 0) return 0;
    [_unicorn memRead:addr buffer:&v size:4];
    return v;
}

- (void)writeGuestUint64:(uint64_t)addr value:(uint64_t)value
{
    [_unicorn memWrite:addr data:&value size:8];
}

- (NSString *)readGuestCString:(uint64_t)addr
{
    if (addr == 0) return @"";
    NSMutableString *str = [NSMutableString string];
    for (NSUInteger i = 0; i < 65536; i++) {
        uint8_t c = 0;
        [_unicorn memRead:(addr + i) buffer:&c size:1];
        if (c == 0) break;
        [str appendFormat:@"%c", c];
    }
    return str;
}

- (void)writeGuestBytes:(uint64_t)addr bytes:(const void *)bytes size:(uint64_t)size
{
    if (size == 0) return;
    [_unicorn memWrite:addr data:bytes size:size];
}

#pragma mark - Memory Service Handlers

- (void)shim_malloc
{
    uint64_t size = [self argumentAtIndex:0];
    if (size > kMaxGuestTransfer || size == 0) {
        if (size > kMaxGuestTransfer) { [self fail:@"shim malloc overflow"]; return; }
        size = 1;
    }
    uint64_t aligned = (size + 15) & ~15ULL;
    uint64_t addr = _heapCursor;
    _heapCursor += aligned;
    if (_heapCursor > kShimHeapBase + kShimHeapSize) {
        [self fail:@"shim heap exhausted"];
        return;
    }
    [self setResult:addr];
}

- (void)shim_malloc_good_size
{
    uint64_t size = [self argumentAtIndex:0];
    [self setResult:((size + 15) & ~15ULL) ?: 16];
}

- (void)shim_malloc_size
{
    [self setResult:32];
}

- (void)shim_calloc
{
    uint64_t count = [self argumentAtIndex:0];
    uint64_t size = [self argumentAtIndex:1];
    if (count != 0 && size > kMaxGuestTransfer / count) {
        [self fail:@"shim calloc overflow"];
        return;
    }
    uint64_t total = count * size;
    if (total == 0) total = 1;
    uint64_t aligned = (total + 15) & ~15ULL;
    uint64_t addr = _heapCursor;
    _heapCursor += aligned;
    if (_heapCursor > kShimHeapBase + kShimHeapSize) {
        [self fail:@"shim heap exhausted (calloc)"];
        return;
    }
    uint8_t *zero = calloc(1, (size_t)aligned);
    [_unicorn memWrite:addr data:zero size:aligned];
    free(zero);
    [self setResult:addr];
}

- (void)shim_realloc
{
    uint64_t ptr = [self argumentAtIndex:0];
    uint64_t newSize = [self argumentAtIndex:1];
    if (newSize > kMaxGuestTransfer) { [self fail:@"shim realloc overflow"]; return; }
    if (newSize == 0) newSize = 1;
    uint64_t aligned = (newSize + 15) & ~15ULL;
    uint64_t newAddr = _heapCursor;
    _heapCursor += aligned;
    if (_heapCursor > kShimHeapBase + kShimHeapSize) {
        [self fail:@"shim heap exhausted (realloc)"];
        return;
    }
    if (ptr != 0) {
        uint8_t *tmp = malloc((size_t)aligned);
        [_unicorn memRead:ptr buffer:tmp size:aligned];
        [_unicorn memWrite:newAddr data:tmp size:aligned];
        free(tmp);
    } else {
        uint8_t *zero = calloc(1, (size_t)aligned);
        [_unicorn memWrite:newAddr data:zero size:aligned];
        free(zero);
    }
    [self setResult:newAddr];
}

- (void)shim_free
{
    [self setResult:0];
}

- (void)shim_memcpy
{
    uint64_t dst = [self argumentAtIndex:0];
    uint64_t src = [self argumentAtIndex:1];
    uint64_t n = [self argumentAtIndex:2];
    if (n > kMaxGuestTransfer) { [self fail:@"shim memcpy overflow"]; return; }
    if (n > 0) {
        uint8_t *tmp = malloc((size_t)n);
        [_unicorn memRead:src buffer:tmp size:n];
        [_unicorn memWrite:dst data:tmp size:n];
        free(tmp);
    }
    [self setResult:dst];
}

- (void)shim_memmove
{
    [self shim_memcpy];
}

- (void)shim_memset
{
    uint64_t dst = [self argumentAtIndex:0];
    int c = (int)[self argumentAtIndex:1];
    uint64_t n = [self argumentAtIndex:2];
    if (n > kMaxGuestTransfer) { [self fail:@"shim memset overflow"]; return; }
    if (n > 0) {
        uint8_t *tmp = calloc(1, (size_t)n);
        memset(tmp, c, (size_t)n);
        [_unicorn memWrite:dst data:tmp size:n];
        free(tmp);
    }
    [self setResult:dst];
}

- (void)shim_bzero
{
    uint64_t dst = [self argumentAtIndex:0];
    uint64_t n = [self argumentAtIndex:1];
    if (n > kMaxGuestTransfer) { [self fail:@"shim bzero overflow"]; return; }
    if (n > 0) {
        uint8_t *tmp = calloc(1, (size_t)n);
        [_unicorn memWrite:dst data:tmp size:n];
        free(tmp);
    }
    [self setResult:dst];
}

- (void)shim_memcpy_chk
{
    uint64_t n = [self argumentAtIndex:2];
    uint64_t cap = [self argumentAtIndex:3];
    if (n > cap) { [self fail:@"shim memcpy_chk overflow"]; return; }
    [self shim_memcpy];
}

- (void)shim_memset_chk
{
    uint64_t n = [self argumentAtIndex:2];
    uint64_t cap = [self argumentAtIndex:3];
    if (n > cap) { [self fail:@"shim memset_chk overflow"]; return; }
    [self shim_memset];
}

- (void)shim_memcmp
{
    uint64_t a = [self argumentAtIndex:0];
    uint64_t b = [self argumentAtIndex:1];
    uint64_t n = [self argumentAtIndex:2];
    if (n > kMaxGuestTransfer) { [self fail:@"shim memcmp overflow"]; return; }
    int diff = 0;
    if (n > 0) {
        uint8_t *ta = malloc((size_t)n), *tb = malloc((size_t)n);
        [_unicorn memRead:a buffer:ta size:n];
        [_unicorn memRead:b buffer:tb size:n];
        diff = memcmp(ta, tb, (size_t)n);
        free(ta); free(tb);
    }
    [self setResult:diff];
}

- (void)shim_strlen
{
    uint64_t addr = [self argumentAtIndex:0];
    uint64_t len = 0;
    for (uint64_t i = 0; i < 65536; i++) {
        uint8_t c = 0;
        [_unicorn memRead:(addr + i) buffer:&c size:1];
        if (c == 0) break;
        len++;
    }
    [self setResult:len];
}

- (void)shim_strcmp
{
    uint64_t a = [self argumentAtIndex:0];
    uint64_t b = [self argumentAtIndex:1];
    for (uint64_t i = 0; i < 65536; i++) {
        uint8_t ca = 0, cb = 0;
        [_unicorn memRead:(a + i) buffer:&ca size:1];
        [_unicorn memRead:(b + i) buffer:&cb size:1];
        if (ca != cb) { [self setResult:(int64_t)(ca - cb)]; return; }
        if (ca == 0) { [self setResult:0]; return; }
    }
    [self setResult:0];
}

- (void)shim_strncmp
{
    uint64_t a = [self argumentAtIndex:0];
    uint64_t b = [self argumentAtIndex:1];
    uint64_t n = [self argumentAtIndex:2];
    for (uint64_t i = 0; i < n; i++) {
        uint8_t ca = 0, cb = 0;
        [_unicorn memRead:(a + i) buffer:&ca size:1];
        [_unicorn memRead:(b + i) buffer:&cb size:1];
        if (ca != cb) { [self setResult:(int64_t)(ca - cb)]; return; }
        if (ca == 0) { [self setResult:0]; return; }
    }
    [self setResult:0];
}

- (void)shim_strcpy
{
    uint64_t dst = [self argumentAtIndex:0];
    uint64_t src = [self argumentAtIndex:1];
    for (uint64_t i = 0; i < 65536; i++) {
        uint8_t c = 0;
        [_unicorn memRead:(src + i) buffer:&c size:1];
        [_unicorn memWrite:(dst + i) data:&c size:1];
        if (c == 0) break;
    }
    [self setResult:dst];
}

- (void)shim_strncpy
{
    uint64_t dst = [self argumentAtIndex:0];
    uint64_t src = [self argumentAtIndex:1];
    uint64_t n = [self argumentAtIndex:2];
    for (uint64_t i = 0; i < n; i++) {
        uint8_t c = 0;
        [_unicorn memRead:(src + i) buffer:&c size:1];
        [_unicorn memWrite:(dst + i) data:&c size:1];
        if (c == 0) {
            for (uint64_t j = i + 1; j < n; j++) {
                uint8_t z = 0;
                [_unicorn memWrite:(dst + j) data:&z size:1];
            }
            break;
        }
    }
    [self setResult:dst];
}

- (void)shim_strdup
{
    uint64_t src = [self argumentAtIndex:0];
    uint64_t len = 0;
    for (uint64_t i = 0; i < 65536; i++) {
        uint8_t c = 0;
        [_unicorn memRead:(src + i) buffer:&c size:1];
        if (c == 0) { len = i; break; }
    }
    uint64_t aligned = (len + 1 + 15) & ~15ULL;
    uint64_t dst = _heapCursor;
    _heapCursor += aligned;
    if (_heapCursor > kShimHeapBase + kShimHeapSize) {
        [self fail:@"shim heap exhausted (strdup)"];
        return;
    }
    uint8_t *tmp = malloc((size_t)(len + 1));
    [_unicorn memRead:src buffer:tmp size:(len + 1)];
    [_unicorn memWrite:dst data:tmp size:(len + 1)];
    free(tmp);
    [self setResult:dst];
}

- (void)shim_strerror { [self setResult:0]; }

- (void)shim_atoi
{
    uint64_t addr = [self argumentAtIndex:0];
    NSString *str = [self readGuestCString:addr];
    [self setResult:(int64_t)[str intValue]];
}

- (void)shim_atol
{
    uint64_t addr = [self argumentAtIndex:0];
    NSString *str = [self readGuestCString:addr];
    [self setResult:(int64_t)[str longLongValue]];
}

- (void)shim_strtoul
{
    uint64_t addr = [self argumentAtIndex:0];
    NSString *str = [self readGuestCString:addr];
    unsigned long long val = strtoull(str.UTF8String, NULL, 10);
    [self setResult:val];
}

- (void)shim_strtoull
{
    [self shim_strtoul];
}

#pragma mark - String Formatting

- (int)writeFormattedStringTo:(uint64_t)outAddr capacity:(int)capacity format:(uint64_t)fmtAddr firstArgIndex:(int)firstIdx
{
    NSString *fmt = [self readGuestCString:fmtAddr];
    const char *f = [fmt UTF8String];
    NSUInteger flen = strlen(f);

    NSMutableData *out = [NSMutableData dataWithCapacity:capacity > 0 ? (NSUInteger)capacity : 256];
    int argIdx = firstIdx;
    NSUInteger i = 0;

    while (i < flen && (capacity <= 0 || out.length < (NSUInteger)capacity)) {
        char c = f[i];
        if (c != '%') {
            [out appendBytes:&c length:1];
            i++;
            continue;
        }
        i++;
        if (i >= flen) break;
        if (f[i] == '%') {
            char p = '%';
            [out appendBytes:&p length:1];
            i++;
            continue;
        }

        while (i < flen && strchr("-+ #0", f[i])) i++;
        while (i < flen && isdigit(f[i])) i++;
        if (i < flen && f[i] == '.') {
            i++;
            while (i < flen && isdigit(f[i])) i++;
        }
        int isLongLong = 0, isLong = 0;
        while (i < flen && strchr("hlLzjt", f[i])) {
            if (f[i] == 'l') {
                if (i + 1 < flen && f[i + 1] == 'l') { isLongLong = 1; i += 2; continue; }
                isLong = 1;
            }
            i++;
        }
        if (i >= flen) break;
        char conv = f[i];
        i++;

        uint64_t raw = [self argumentAtIndex:argIdx];

        char tmp[64];
        int len = 0;
        switch (conv) {
            case 'd':
            case 'i': {
                int64_t v = (int32_t)(uint32_t)raw;
                if (isLong || isLongLong) v = (int64_t)raw;
                len = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
                break;
            }
            case 'u':
            case 'x':
            case 'X':
            case 'o': {
                uint64_t v = (uint32_t)raw;
                if (isLong || isLongLong) v = raw;
                snprintf(tmp, sizeof(tmp), conv == 'X' ? "%llX" : (conv == 'o' ? "%llo" : (conv == 'x' ? "%llx" : "%llu")), (unsigned long long)v);
                len = (int)strlen(tmp);
                break;
            }
            case 'c': {
                tmp[0] = (char)(uint8_t)raw;
                len = 1;
                break;
            }
            case 'p': {
                len = snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)raw);
                break;
            }
            case 's': {
                NSString *s = raw ? [self readGuestCString:raw] : @"(null)";
                const char *cs = [s UTF8String];
                size_t slen = strlen(cs);
                if (out.length + slen <= (NSUInteger)capacity || capacity <= 0) {
                    [out appendBytes:cs length:slen];
                }
                len = -1;
                break;
            }
            case 'n':
                [self writeGuestUint64:raw value:(uint64_t)out.length];
                len = -1;
                argIdx--;
                break;
            default:
                break;
        }

        if (len >= 0) {
            if (capacity > 0 && out.length + (NSUInteger)len > (NSUInteger)capacity) {
                len = capacity - (int)out.length;
                if (len > 0) [out appendBytes:tmp length:(NSUInteger)len];
                break;
            }
            [out appendBytes:tmp length:(NSUInteger)len];
        }
        argIdx++;
    }

    if (capacity > 0 && out.length >= (NSUInteger)capacity) {
        // leave room for NUL
    }

    if (outAddr != 0) {
        _unicorn memWrite:outAddr data:out.bytes size:out.length;
        uint8_t nul = 0;
        [_unicorn memWrite:(outAddr + out.length) data:&nul size:1];
    }

    return (int)out.length;
}

- (void)shim_snprintf
{
    uint64_t outAddr = [self argumentAtIndex:0];
    uint64_t size = [self argumentAtIndex:1];
    uint64_t fmtAddr = [self argumentAtIndex:2];
    int written = [self writeFormattedStringTo:outAddr capacity:(size > 0 ? (int)MIN(size, 8192) : 0) format:fmtAddr firstArgIndex:3];
    [self setResult:(uint64_t)written];
}

- (void)shim_sprintf
{
    uint64_t outAddr = [self argumentAtIndex:0];
    uint64_t fmtAddr = [self argumentAtIndex:1];
    int written = [self writeFormattedStringTo:outAddr capacity:0 format:fmtAddr firstArgIndex:2];
    [self setResult:(uint64_t)written];
}

#pragma mark - Platform Service Handlers

- (void)shim_open
{
    uint64_t pathAddr = [self argumentAtIndex:0];
    NSString *path = [self readGuestCString:pathAddr];
    _icxsCursor = 0;
    if ([path isEqualToString:@"./../CoreFP.icxs"] || [path hasSuffix:@"CoreFP.icxs"]) {
        if (WFSSAPTraceEnabled()) {
            NSLog(@"[WFS-SAP] open %@ -> fd %d", path, kCoreFPFileFd);
        }
        [self setResult:kCoreFPFileFd];
        return;
    }
    if (WFSSAPTraceEnabled()) {
        NSLog(@"[WFS-SAP] open %@ -> -1", path);
    }
    [self setResult:0xFFFFFFFFFFFFFFFFULL];
}

- (void)shim_read
{
    uint64_t fd = [self argumentAtIndex:0];
    uint64_t buf = [self argumentAtIndex:1];
    uint64_t count = [self argumentAtIndex:2];
    if (fd != kCoreFPFileFd) {
        [self setResult:0xFFFFFFFFFFFFFFFFULL];
        return;
    }
    NSUInteger remaining = _icxs.length - _icxsCursor;
    NSUInteger size = (NSUInteger)MIN(count, remaining);
    if (size > 0) {
        const uint8_t *bytes = _icxs.bytes + _icxsCursor;
        [_unicorn memWrite:buf data:bytes size:size];
        _icxsCursor += size;
    }
    [self setResult:size];
}

- (void)shim_close
{
    [self setResult:0];
}

- (void)shim_gettimeofday
{
    uint64_t tvAddr = [self argumentAtIndex:0];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t sec = (uint64_t)tv.tv_sec;
    uint32_t usec = (uint32_t)tv.tv_usec;
    uint32_t pad = 0;
    if (tvAddr != 0) {
        [_unicorn memWrite:tvAddr data:&sec size:8];
        [_unicorn memWrite:(tvAddr + 8) data:&usec size:4];
        [_unicorn memWrite:(tvAddr + 12) data:&pad size:4];
        uint64_t tz = 0;
        [_unicorn memWrite:(tvAddr + 16) data:&tz size:8];
    }
    [self setResult:0];
}

- (void)shim_sysctlbyname
{
    uint64_t oldlenp = [self argumentAtIndex:3];
    if (oldlenp != 0) {
        uint64_t zero = 0;
        [_unicorn memWrite:oldlenp data:&zero size:8];
    }
    [self setResult:0];
}

- (void)shim_pthread_once
{
    uint64_t onceAddr = [self argumentAtIndex:0];
    uint64_t initFn = [self argumentAtIndex:1];
    if (onceAddr == 0) { [self setResult:0]; return; }
    uint64_t onceVal = [self readGuestUint64:onceAddr];
    if (onceVal == 0) {
        [self setResult:0];
        return;
    }
    [self writeGuestUint64:onceAddr value:0];
    uint64_t rsp = [_unicorn regReadU64:UC_X86_REG_RSP];
    uint64_t newRsp = rsp - 8;
    [self writeGuestUint64:newRsp value:initFn];
    [_unicorn regWriteU64:UC_X86_REG_RSP :newRsp];
    [self setResult:0];
}

- (void)shim_OSAtomicCompareAndSwap32Barrier
{
    uint64_t old = [self argumentAtIndex:0];
    int32_t newv = (int32_t)[self argumentAtIndex:1];
    uint64_t ptr = [self argumentAtIndex:2];
    int32_t cur = [self readGuestUint32:ptr];
    if ((uint32_t)cur == (uint32_t)old) {
        [_unicorn memWrite:ptr data:&newv size:4];
        [self setResult:1];
    } else {
        [self setResult:0];
    }
}

- (void)shim_error
{
    [self setResult:_errnoAddr];
}

- (void)shim_arc4random
{
    uint32_t r = arc4random();
    [self setResult:r];
}

- (void)shim_dlsym
{
    uint64_t nameAddr = [self argumentAtIndex:1];
    NSString *name = [self readGuestCString:nameAddr];
    if (_symbols[name]) {
        [self setResult:_symbols[name].unsignedLongLongValue];
        return;
    }
    NSNumber *exportAddr = _coreExports[name];
    if (exportAddr) {
        [self setResult:exportAddr.unsignedLongLongValue];
        return;
    }
    if (WFSSAPTraceEnabled()) {
        NSLog(@"[WFS-SAP] dlsym %@ -> NULL", name);
    }
    [self setResult:0];
}

- (void)shim_dlopen
{
    uint64_t pathAddr = [self argumentAtIndex:0];
    NSString *path = [self readGuestCString:pathAddr];
    if ([path containsString:@"CoreFP.framework"]) {
        [self setResult:kFakeHandle];
    } else {
        [self setResult:0];
    }
}

- (void)shim_objc_msgSend
{
    uint64_t selAddr = [self argumentAtIndex:1];
    NSString *sel = [self readGuestCString:selAddr];
    if ([sel isEqualToString:@"objectForKey:"]) {
        [self setResult:kFakeHandle];
    } else {
        [self setResult:0];
    }
}

- (void)shim_fake { [self setResult:kFakeHandle]; }
- (void)shim_zero { [self setResult:0]; }
- (void)shim_minusone { [self setResult:0xFFFFFFFFFFFFFFFFULL]; }

- (void)shim_abort
{
    [self fail:@"guest aborted (abort/stack_chk_fail/dyld_stub_binder)"];
}

- (void)shim_cfStringCreateWithCString
{
    uint64_t bytes = [self argumentAtIndex:1];
    NSString *value = [self readGuestCString:bytes];
    if ([value isEqualToString:@"IOPlatformSerialNumber"] ||
        [value isEqualToString:@"IOPlatformUUID"] ||
        [value isEqualToString:@"board-id"]) {
        [self setResult:kFakeHandle];
    } else {
        [self setResult:0];
    }
}

- (void)shim_cfStringGetCString
{
    uint64_t buf = [self argumentAtIndex:1];
    uint64_t cap = [self argumentAtIndex:2];
    if (buf != 0 && cap > 0) {
        uint8_t nul = 0;
        [_unicorn memWrite:buf data:&nul size:1];
        [self setResult:1];
    } else {
        [self setResult:0];
    }
}

- (void)shim_ioIteratorNext
{
    _iterator++;
    [self setResult:_iterator % 2];
}

- (void)shim_ioServiceGetMatchingService
{
    [self setResult:0xFFFFFFFFULL];
}

- (void)shim_ioServiceGetMatchingServices
{
    _iterator = 0;
    uint64_t iterOut = [self argumentAtIndex:2];
    if (iterOut != 0) {
        uint32_t v = 0xFFFFFFFF;
        [_unicorn memWrite:iterOut data:&v size:4];
    }
    [self setResult:0];
}

- (void)shim_ioRegistryEntryGetParentEntry
{
    uint64_t parentOut = [self argumentAtIndex:2];
    if (parentOut != 0) {
        uint32_t v = 0xFFFFFFFF;
        [_unicorn memWrite:parentOut data:&v size:4];
    }
    [self setResult:0];
}

- (void)shim_ioServiceOpen { [self setResult:0xFFFFFFFFULL]; }

- (void)shim_ioConnectCallMethod { [self setResult:0]; }

- (void)shim_SecRandomCopyBytes
{
    uint64_t dst = [self argumentAtIndex:1];
    uint64_t len = [self argumentAtIndex:2];
    if (len > 0 && len <= kMaxGuestTransfer) {
        uint8_t *tmp = malloc((size_t)len);
        arc4random_buf(tmp, (size_t)len);
        [_unicorn memWrite:dst data:tmp size:len];
        free(tmp);
    }
    [self setResult:0];
}

- (void)shim_CC_SHA1
{
    [self runDigest:CC_SHA1_DIGEST_LENGTH block:^(const uint8_t *data, CC_LONG len, uint8_t *md) {
        CC_SHA1(data, len, md);
    } firstArg:0];
}

- (void)shim_CC_SHA256
{
    [self runDigest:CC_SHA256_DIGEST_LENGTH block:^(const uint8_t *data, CC_LONG len, uint8_t *md) {
        CC_SHA256(data, len, md);
    } firstArg:0];
}

- (void)shim_CC_MD5
{
    [self runDigest:CC_MD5_DIGEST_LENGTH block:^(const uint8_t *data, CC_LONG len, uint8_t *md) {
        CC_MD5(data, len, md);
    } firstArg:0];
}

- (void)runDigest:(unsigned int)digestLen
            block:(void(^)(const uint8_t *, CC_LONG, uint8_t *))block
         firstArg:(int)firstArg
{
    uint64_t dataAddr = [self argumentAtIndex:firstArg];
    uint64_t len = [self argumentAtIndex:firstArg + 1];
    uint64_t mdAddr = [self argumentAtIndex:firstArg + 2];
    if (len > kMaxGuestTransfer) { [self fail:@"digest input too large"]; return; }
    if (mdAddr == 0) { [self setResult:0]; return; }
    uint8_t *data = len > 0 ? malloc((size_t)len) : NULL;
    if (len > 0) [_unicorn memRead:dataAddr buffer:data size:len];
    uint8_t md[CC_SHA512_DIGEST_LENGTH];
    block(data, (CC_LONG)MIN(len, (uint64_t)CC_LONG_MAX), md);
    [_unicorn memWrite:mdAddr data:md size:digestLen];
    if (data) free(data);
    [self setResult:mdAddr];
}

- (void)shim_CCHmac
{
    uint64_t alg = [self argumentAtIndex:0];
    uint64_t keyAddr = [self argumentAtIndex:1];
    uint64_t keyLen = [self argumentAtIndex:2];
    uint64_t dataAddr = [self argumentAtIndex:3];
    uint64_t dataLen = [self argumentAtIndex:4];
    uint64_t macOut = [self argumentAtIndex:5];
    if (alg >= 6 || macOut == 0) { [self setResult:0]; return; }
    if (keyLen > kMaxGuestTransfer || dataLen > kMaxGuestTransfer) { [self fail:@"hmac input too large"]; return; }
    uint8_t *key = keyLen > 0 ? malloc((size_t)keyLen) : NULL;
    uint8_t *data = dataLen > 0 ? malloc((size_t)dataLen) : NULL;
    if (keyLen > 0) [_unicorn memRead:keyAddr buffer:key size:keyLen];
    if (dataLen > 0) [_unicorn memRead:dataAddr buffer:data size:dataLen];
    uint8_t mac[CC_SHA512_DIGEST_LENGTH];
    CCHmac((CCHmacAlgorithm)alg, key, (size_t)keyLen, data, (size_t)dataLen, mac);
    [_unicorn memWrite:macOut data:mac size:CCHmacOutputSize((CCHmacAlgorithm)alg)];
    if (key) free(key);
    if (data) free(data);
    [self setResult:0];
}

- (void)shim_unsupported
{
    [self setResult:0];
}

#pragma mark - Lifecycle

- (void)close
{
}

- (void)dealloc
{
    [self close];
}

- (NSError *)shimError:(NSString *)message
{
    return [NSError errorWithDomain:@"WFSSAPShims" code:-1
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

@end