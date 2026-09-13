#import "WFSSAPShims.h"
#import "WaffleStore-Swift.h"
#import <mach-o/loader.h>

static const uint64_t kShimBase     = 0x0000200000000000;
static const uint64_t kShimCodeSize = 0x80000;
static const uint64_t kShimSize     = 0x100000;
static const uint64_t kShimSlotSize = 16;

static const uint64_t kShimHeapBase = 0x0000600000000000;
static const uint64_t kShimHeapSize = 16 << 20;

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
    void *_hook;
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

    if (![self registerMemoryServices:error]) return nil;
    if (![self registerPlatformServices:error]) return nil;

    if (icxs && icxs.length > 0) {
        [self registerICXSServices:icxs coreExports:coreExports];
    }

    return self;
}

#pragma mark - Memory Services

- (BOOL)registerMemoryServices:(NSError **)error
{
    [self addFunction:@"_uc_ctl_set_page_permissions" handler:@selector(shim_uc_ctl_set_page_permissions)];
    [self addFunction:@"_uc_ctl_get_loader_metadata" handler:@selector(shim_uc_ctl_get_loader_metadata)];
    [self addFunction:@"_malloc" handler:@selector(shim_malloc)];
    [self addFunction:@"_calloc" handler:@selector(shim_calloc)];
    [self addFunction:@"_realloc" handler:@selector(shim_realloc)];
    [self addFunction:@"_free" handler:@selector(shim_free)];
    [self addFunction:@"_memcpy" handler:@selector(shim_memcpy)];
    [self addFunction:@"_memset" handler:@selector(shim_memset)];
    [self addFunction:@"_memmove" handler:@selector(shim_memmove)];
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
    [self addFunction:@"_qsort" handler:@selector(shim_qsort)];
    [self addFunction:@"_bsearch" handler:@selector(shim_bsearch)];
    return YES;
}

#pragma mark - Platform Services (IOKit stubs)

- (BOOL)registerPlatformServices:(NSError **)error
{
    [self addFunction:@"_IOServiceMatching" handler:@selector(shim_IOServiceMatching)];
    [self addFunction:@"_IOServiceGetMatchingService" handler:@selector(shim_IOServiceGetMatchingService)];
    [self addFunction:@"_IORegistryEntryCreateCFProperty" handler:@selector(shim_IORegistryEntryCreateCFProperty)];
    [self addFunction:@"_IOObjectConformsTo" handler:@selector(shim_IOObjectConformsTo)];
    [self addFunction:@"_IOServiceOpen" handler:@selector(shim_IOServiceOpen)];
    [self addFunction:@"_IOConnectCallMethod" handler:@selector(shim_IOConnectCallMethod)];
    [self addFunction:@"_IOCFSerialize" handler:@selector(shim_IOCFSerialize)];
    [self addFunction:@"_IOObjectRelease" handler:@selector(shim_IOObjectRelease)];
    [self addFunction:@"_IOServiceClose" handler:@selector(shim_IOServiceClose)];
    [self addFunction:@"_IORegistryEntrySearchCFProperty" handler:@selector(shim_IORegistryEntrySearchCFProperty)];

    [self addFunction:@"_SecRandomCopyBytes" handler:@selector(shim_SecRandomCopyBytes)];
    [self addFunction:@"_SecKeyCreateSignature" handler:@selector(shim_SecKeyCreateSignature)];
    [self addFunction:@"_SecKeyCreateRandomKey" handler:@selector(shim_SecKeyCreateRandomKey)];
    [self addFunction:@"_SecKeyCopyPublicKey" handler:@selector(shim_SecKeyCopyPublicKey)];
    [self addFunction:@"_SecKeyCopyExternalRepresentation" handler:@selector(shim_SecKeyCopyExternalRepresentation)];
    [self addFunction:@"_SecKeyCopyAttributes" handler:@selector(shim_SecKeyCopyAttributes)];

    [self addFunction:@"_CC_SHA1" handler:@selector(shim_CC_SHA1)];
    [self addFunction:@"_CC_SHA256" handler:@selector(shim_CC_SHA256)];
    [self addFunction:@"_CC_MD5" handler:@selector(shim_CC_MD5)];
    [self addFunction:@"_CCHmac" handler:@selector(shim_CCHmac)];

    return YES;
}

#pragma mark - ICXS Services

- (void)registerICXSServices:(NSData *)icxs coreExports:(NSDictionary<NSString *, NSNumber *> *)coreExports
{
    const uint8_t *bytes = icxs.bytes;
    NSUInteger length = icxs.length;

    if (length < 4) return;

    uint32_t magic = 0;
    memcpy(&magic, bytes, 4);

    if (magic != 0x58534349 && magic != 0x49435853) {
        return;
    }

    if (length < 16) return;

    uint32_t count = 0;
    memcpy(&count, bytes + 8, 4);
    count = CFSwapInt32LittleToHost(count);

    uint32_t tableOffset = 0;
    memcpy(&tableOffset, bytes + 12, 4);
    tableOffset = CFSwapInt32LittleToHost(tableOffset);

    for (uint32_t i = 0; i < count && tableOffset + i * 16 + 16 <= length; i++) {
        uint32_t nameOffset = 0, codeOffset = 0, codeSize = 0;
        memcpy(&nameOffset, bytes + tableOffset + i * 16, 4);
        memcpy(&codeOffset, bytes + tableOffset + i * 16 + 4, 4);
        memcpy(&codeSize, bytes + tableOffset + i * 16 + 8, 4);

        nameOffset = CFSwapInt32LittleToHost(nameOffset);
        codeOffset = CFSwapInt32LittleToHost(codeOffset);
        codeSize = CFSwapInt32LittleToHost(codeSize);

        if (nameOffset >= length || codeOffset >= length || codeSize == 0) continue;

        const char *namePtr = (const char *)(bytes + nameOffset);
        NSUInteger nameLen = strnlen(namePtr, length - nameOffset);
        NSString *name = [[NSString alloc] initWithBytes:namePtr length:nameLen encoding:NSUTF8StringEncoding];
        if (!name.length || [name characterAtIndex:0] != '_') continue;

        if (_symbols[name]) continue;

        if (codeSize <= kShimSlotSize && codeOffset + codeSize <= length) {
            uint64_t addr = _codeCursor;
            _codeCursor += kShimSlotSize;
            const void *codePtr = bytes + codeOffset;
            [_unicorn memWrite:addr data:codePtr size:codeSize];
            _symbols[name] = @(addr);
        }
    }
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
    WFSSAPShimEntry *entry = _entries[@(address)];
    if (!entry) {
        [self fail:[NSString stringWithFormat:@"guest entered unknown shim address %#llx", address]];
        return;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    if ([self respondsToSelector:entry.handler]) {
        [self performSelector:entry.handler];
    } else {
        [self fail:[NSString stringWithFormat:@"shim handler not found for %@", entry.name]];
    }
#pragma clang diagnostic pop
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
    [_unicorn regWriteU64:UC_X86_REG_RAX value];
}

- (uint64_t)readGuestUint64:(uint64_t)addr
{
    uint64_t v = 0;
    [_unicorn memRead:addr buffer:&v size:8];
    return v;
}

- (uint32_t)readGuestUint32:(uint64_t)addr
{
    uint32_t v = 0;
    [_unicorn memRead:addr buffer:&v size:4];
    return v;
}

- (void)writeGuestUint64:(uint64_t)addr value:(uint64_t)value
{
    [_unicorn memWrite:addr data:&value size:8];
}

- (NSString *)readGuestCString:(uint64_t)addr
{
    NSMutableString *str = [NSMutableString string];
    for (NSUInteger i = 0; i < 4096; i++) {
        uint8_t c = 0;
        [_unicorn memRead:(addr + i) buffer:&c size:1];
        if (c == 0) break;
        [str appendFormat:@"%c", c];
    }
    return str;
}

#pragma mark - Memory Service Handlers

- (void)shim_malloc
{
    uint64_t size = [self argumentAtIndex:0];
    if (size == 0) size = 1;
    uint64_t aligned = (size + 15) & ~15ULL;
    uint64_t addr = _heapCursor;
    _heapCursor += aligned;
    if (_heapCursor > kShimHeapBase + kShimHeapSize) {
        [self fail:@"shim heap exhausted"];
        return;
    }
    [self setResult:addr];
}

- (void)shim_calloc
{
    uint64_t count = [self argumentAtIndex:0];
    uint64_t size = [self argumentAtIndex:1];
    uint64_t total = count * size;
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
    if (n > 0) {
        uint8_t *tmp = malloc((size_t)n);
        [_unicorn memRead:src buffer:tmp size:n];
        [_unicorn memWrite:dst data:tmp size:n];
        free(tmp);
    }
    [self setResult:dst];
}

- (void)shim_memset
{
    uint64_t dst = [self argumentAtIndex:0];
    int c = (int)[self argumentAtIndex:1];
    uint64_t n = [self argumentAtIndex:2];
    if (n > 0) {
        uint8_t *tmp = calloc(1, (size_t)n);
        memset(tmp, c, (size_t)n);
        [_unicorn memWrite:dst data:tmp size:n];
        free(tmp);
    }
    [self setResult:dst];
}

- (void)shim_memmove
{
    uint64_t dst = [self argumentAtIndex:0];
    uint64_t src = [self argumentAtIndex:1];
    uint64_t n = [self argumentAtIndex:2];
    if (n > 0) {
        uint8_t *tmp = malloc((size_t)n);
        [_unicorn memRead:src buffer:tmp size:n];
        [_unicorn memWrite:dst data:tmp size:n];
        free(tmp);
    }
    [self setResult:dst];
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

- (void)shim_snprintf
{
    [self setResult:0];
}

- (void)shim_sprintf
{
    [self setResult:0];
}

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
    char *end = NULL;
    unsigned long long val = strtoull(str.UTF8String, &end, 10);
    [self setResult:val];
}

- (void)shim_strtoull
{
    uint64_t addr = [self argumentAtIndex:0];
    NSString *str = [self readGuestCString:addr];
    char *end = NULL;
    unsigned long long val = strtoull(str.UTF8String, &end, 10);
    [self setResult:val];
}

- (void)shim_qsort { }
- (void)shim_bsearch { [self setResult:0]; }

#pragma mark - Platform Service Handlers

- (void)shim_IOServiceMatching { [self setResult:0]; }
- (void)shim_IOServiceGetMatchingService { [self setResult:0]; }
- (void)shim_IORegistryEntryCreateCFProperty { [self setResult:0]; }
- (void)shim_IOObjectConformsTo { [self setResult:0]; }
- (void)shim_IOServiceOpen { [self setResult:0]; }
- (void)shim_IOConnectCallMethod { [self setResult:0]; }
- (void)shim_IOCFSerialize { [self setResult:0]; }
- (void)shim_IOObjectRelease { [self setResult:0]; }
- (void)shim_IOServiceClose { [self setResult:0]; }
- (void)shim_IORegistryEntrySearchCFProperty { [self setResult:0]; }

- (void)shim_SecRandomCopyBytes
{
    uint64_t dst = [self argumentAtIndex:1];
    uint64_t len = [self argumentAtIndex:2];
    if (len > 0) {
        uint8_t *tmp = malloc((size_t)len);
        arc4random_buf(tmp, (size_t)len);
        [_unicorn memWrite:dst data:tmp size:len];
        free(tmp);
    }
    [self setResult:0];
}

- (void)shim_SecKeyCreateSignature { [self setResult:0xFFFFFFFF]; }
- (void)shim_SecKeyCreateRandomKey { [self setResult:0]; }
- (void)shim_SecKeyCopyPublicKey { [self setResult:0]; }
- (void)shim_SecKeyCopyExternalRepresentation { [self setResult:0]; }
- (void)shim_SecKeyCopyAttributes { [self setResult:0]; }

- (void)shim_CC_SHA1 { [self setResult:20]; }
- (void)shim_CC_SHA256 { [self setResult:32]; }
- (void)shim_CC_MD5 { [self setResult:16]; }
- (void)shim_CCHmac { }

- (void)shim_uc_ctl_set_page_permissions { [self setResult:0]; }
- (void)shim_uc_ctl_get_loader_metadata { [self setResult:0]; }
- (void)shim_unsupported { [self setResult:0]; }

#pragma mark - Lifecycle

- (void)close
{
    if (_hook) {
        [_unicorn hookDel:_hook];
        _hook = NULL;
    }
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
