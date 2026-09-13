#import "WFSSAPMachine.h"
#import "WFSUnicorn.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>

static const uint64_t kReturnAddress   = 0x0000000100000000;
static const uint64_t kCoreFPBase      = 0x0000100000000000;
static const uint64_t kCommerceBase    = 0x0000100040000000;
static const uint64_t kKitBase         = 0x0000100080000000;
static const uint64_t kScratchBase     = 0x0000300000000000;
static const uint64_t kScratchSize     = 32 << 20;
static const uint64_t kHeapBase        = 0x0000400000000000;
static const uint64_t kHeapSize        = 64 << 20;
static const uint64_t kStackBase       = 0x0000500000000000;
static const uint64_t kStackSize       = 8 << 20;
static const uint64_t kPageSize        = 0x1000;
static const uint64_t kMaxOutputSize   = 16 << 20;
static const int      kSAPGuestTimeout = 60;

static NSString *const kCoreFPExportNames[] = {
    @"_WIn9UJ86JKdV4dM",
    @"_X46O5IeS",
    @"_YlCJ3lg",
    @"_dku592fbFAj",
    @"_fdjkDSAFjklaf2s",
    @"_lxpgvVMLd0S7uRl",
};

static NSString *const kEntryNames[] = {
    @"_cp2g1b9ro",
    @"_Mib5yocT",
    @"_Fc3vhtJDvr",
    @"_IPaI1oem5iL",
    @"_jEHf8Xzsv8K",
};

@interface WFSSAPMachOImage : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, strong) NSData *data;
@property (nonatomic, assign) uint64_t base;
@property (nonatomic, assign) uint64_t textOffset;
@property (nonatomic, strong) NSArray<NSDictionary *> *segments;
@property (nonatomic, strong) NSArray<NSDictionary *> *rebases;
@property (nonatomic, strong) NSArray<NSDictionary *> *binds;
@property (nonatomic, strong) NSDictionary<NSString *, NSNumber *> *exports;
@property (nonatomic, assign) BOOL relocated;
@property (nonatomic, assign) uint64_t loadedBase;
@end

@implementation WFSSAPMachOImage
@end

@interface WFSSAPMachine ()
@property (nonatomic, strong) WFSUnicornAPI unicorn;
@property (nonatomic, assign) uc_engine engine;
@property (nonatomic, strong) WFSSAPMachOImage *coreFPImage;
@property (nonatomic, strong) WFSSAPMachOImage *commerceCoreImage;
@property (nonatomic, strong) WFSSAPMachOImage *commerceKitImage;
@property (nonatomic, strong) NSDictionary<NSString *, NSNumber *> *coreFPExports;
@property (nonatomic, strong) NSDictionary<NSString *, NSNumber *> *resolvedEntries;
@property (nonatomic, assign) uint64_t scratchCursor;
@property (nonatomic, assign) BOOL closed;
@property (nonatomic, assign) uint64_t shimMacAddress;
@end

@implementation WFSSAPMachine

+ (nullable instancetype)openWithCoreFP:(NSData *)coreFP
                           commerceCore:(NSData *)commerceCore
                           commerceKit:(NSData *)commerceKit
                             coreFPICXS:(NSData *)coreFPICXS
                                  error:(NSError **)error
{
    return [[self alloc] initWithCoreFP:coreFP commerceCore:commerceCore commerceKit:commerceKit coreFPICXS:coreFPICXS error:error];
}

- (nullable instancetype)initWithCoreFP:(NSData *)coreFPData
                            commerceCore:(NSData *)commerceCoreData
                            commerceKit:(NSData *)commerceKitData
                              coreFPICXS:(NSData *)coreFPICXS
                                   error:(NSError **)error
{
    self = [super init];
    if (!self) return nil;

    if (wfs_unicorn_load(&_unicorn) != 0) {
        if (error) *error = [self error:@"Failed to load Unicorn library. Install libunicorn.dylib."];
        return nil;
    }

    uint32_t major = 0, minor = 0;
    _unicorn.version(&major, &minor);
    if (major != 2 || minor < 1) {
        if (error) *error = [self error:[NSString stringWithFormat:@"Unicorn API version %d.%d unsupported (need 2.1+)", major, minor]];
        return nil;
    }

    int rc = _unicorn.open(UC_ARCH_X86, UC_MODE_64, &_engine);
    if (rc != 0) {
        if (error) *error = [self error:[NSString stringWithFormat:@"uc_open failed: %s", _unicorn.strerror(rc)]];
        return nil;
    }

    BOOL ready = NO;
    @try {
        _coreFPImage = [self openImage:@"CoreFP" data:coreFPData error:error];
        if (!_coreFPImage) return nil;

        _commerceCoreImage = [self openImage:@"CommerceCore" data:commerceCoreData error:error];
        if (!_commerceCoreImage) return nil;

        _commerceKitImage = [self openImage:@"CommerceKit" data:commerceKitData error:error];
        if (!_commerceKitImage) return nil;

        NSMutableDictionary *allExports = [NSMutableDictionary dictionary];
        NSMutableDictionary *coreExports = [NSMutableDictionary dictionary];

        for (NSString *name in [NSArray arrayWithObjects:kCoreFPExportNames count:sizeof(kCoreFPExportNames)/sizeof(kCoreFPExportNames[0])]) {
            uint64_t addr = [_coreFPImage exportAddress:name loadBase:kCoreFPBase error:error];
            if (addr == 0) return nil;
            coreExports[name] = @(addr);
            allExports[name] = @(addr);
        }

        _coreFPExports = coreExports;

        {
            uint64_t addr = [_commerceCoreImage exportAddress:@"_get_mac_address" loadBase:kCommerceBase error:error];
            if (addr == 0) return nil;
            allExports[@"_get_mac_address"] = @(addr);
            _shimMacAddress = addr;
        }

        NSMutableDictionary *entries = [NSMutableDictionary dictionary];
        for (NSString *name in [NSArray arrayWithObjects:kEntryNames count:sizeof(kEntryNames)/sizeof(kEntryNames[0])]) {
            uint64_t addr = [_commerceKitImage exportAddress:name loadBase:kKitBase error:error];
            if (addr == 0) return nil;
            allExports[name] = @(addr);
            entries[name] = @(addr);
        }
        _resolvedEntries = entries;

        [self mapRegions];

        uint8_t hlt = 0xF4;
        [self memWrite:kReturnAddress data:&hlt size:1];

        [_coreFPImage relocate:kCoreFPBase resolver:^uint64_t(NSString *name) {
            NSNumber *addr = allExports[name];
            return addr ? addr.unsignedLongLongValue : 0;
        } error:error];
        if (*error) return nil;

        [_commerceCoreImage relocate:kCommerceBase resolver:^uint64_t(NSString *name) {
            NSNumber *addr = allExports[name];
            return addr ? addr.unsignedLongLongValue : 0;
        } error:error];
        if (*error) return nil;

        [_commerceKitImage relocate:kKitBase resolver:^uint64_t(NSString *name) {
            NSNumber *addr = allExports[name];
            return addr ? addr.unsignedLongLongValue : 0;
        } error:error];
        if (*error) return nil;

        [self loadImage:_coreFPImage error:error];
        if (*error) return nil;
        [self loadImage:_commerceCoreImage error:error];
        if (*error) return nil;
        [self loadImage:_commerceKitImage error:error];
        if (*error) return nil;

        ready = YES;
    } @finally {
        if (!ready) {
            [self close];
        }
    }

    return self;
}

#pragma mark - Mach-O Parsing

- (nullable WFSSAPMachOImage *)openImage:(NSString *)name data:(NSData *)data error:(NSError **)error
{
    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;

    if (length < sizeof(uint32_t)) {
        if (error) *error = [self error:[NSString stringWithFormat:@"%@: data too short", name]];
        return nil;
    }

    uint32_t magic = *(const uint32_t *)bytes;
    NSData *sliceData = data;

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        sliceData = [self extractX86_64Slice:data name:name error:error];
        if (!sliceData) return nil;
        bytes = sliceData.bytes;
        length = sliceData.length;
        magic = *(const uint32_t *)bytes;
    }

    if (magic != MH_MAGIC_64) {
        if (error) *error = [self error:[NSString stringWithFormat:@"%@: not an x86-64 Mach-O (magic=0x%x)", name, magic]];
        return nil;
    }

    const struct mach_header_64 *hdr = (const struct mach_header_64 *)bytes;
    WFSSAPMachOImage *image = [[WFSSAPMachOImage alloc] init];
    image.name = name;
    image.data = sliceData;
    image.base = hdr->reserved;

    NSMutableArray *segments = [NSMutableArray array];
    NSMutableArray *rebases = [NSMutableArray array];
    NSMutableArray *binds = [NSMutableArray array];
    NSMutableDictionary *exports = [NSMutableDictionary dictionary];

    const uint8_t *cmd = bytes + sizeof(struct mach_header_64);
    uint32_t ncmds = hdr->ncmds;

    for (uint32_t i = 0; i < ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;

            NSDictionary *segInfo = @{
                @"name": @(seg->segname),
                @"vmaddr": @(seg->vmaddr),
                @"vmsize": @(seg->vmsize),
                @"fileoff": @(seg->fileoff),
                @"filesize": @(seg->filesize),
            };
            [segments addObject:segInfo];

            const struct section_64 *sec = (const struct section_64 *)(cmd + sizeof(struct segment_command_64));
            uint32_t nsects = (seg->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64);

            for (uint32_t j = 0; j < nsects; j++) {
                uint32_t secType = sec[j].flags & SECTION_TYPE;

                if (secType == S_LAZY_SYMBOL_POINTERS || secType == S_NON_LAZY_SYMBOL_POINTERS) {
                    uint64_t secAddr = sec[j].addr;
                    uint64_t secSize = sec[j].size;
                    uint64_t secOff = sec[j].offset;
                    uint64_t ptrCount = secSize / 8;

                    for (uint64_t k = 0; k < ptrCount; k++) {
                        uint64_t entryOff = secOff + k * 8;
                        [rebases addObject:@{
                            @"segment": @(seg->segname),
                            @"offset": @(secAddr - seg->vmaddr + k * 8),
                            @"fileOffset": @(entryOff),
                        }];
                    }
                }
            }
        }

        if (lc->cmd == LC_DYSYMTAB) {
            const struct dysymtab_info *dysymtab = (const struct dysymtab_info *)cmd;
            const uint8_t *symbytes = bytes;

            uint32_t *indirectSymtab = (uint32_t *)(symbytes + dysymtab->indirectsymoff);
            uint32_t nIndirectSyms = dysymtab->nindirectsyms;

            for (uint32_t j = 0; j < nIndirectSyms; j++) {
                uint32_t symIdx = indirectSymtab[j];
                (void)symIdx;
            }
        }

        if (lc->cmd == LC_SYMTAB) {
            const struct symtab_info *symtab = (const struct symtab_info *)cmd;
            const uint8_t *strtab = bytes + symtab->stroff;
            const struct nlist_64 *syms = (const struct nlist_64 *)(bytes + symtab->symoff);

            for (uint32_t j = 0; j < symtab->nsyms; j++) {
                if (syms[j].n_value == 0) continue;
                if (syms[j].n_type & N_STAB) continue;

                const char *symName = (const char *)(strtab + syms[j].n_un.n_strx);
                if (symName[0] != '_') continue;

                exports[@(symName)] = @(syms[j].n_value);
            }
        }

        cmd += lc->cmdsize;
    }

    image.segments = segments;
    image.rebases = rebases;
    image.binds = binds;
    image.exports = exports;

    return image;
}

- (nullable NSData *)extractX86_64Slice:(NSData *)data name:(NSString *)name error:(NSError **)error
{
    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;

    if (length < sizeof(struct fat_header)) {
        if (error) *error = [self error:[NSString stringWithFormat:@"%@: fat header too short", name]];
        return nil;
    }

    const struct fat_header *fhdr = (const struct fat_header *)bytes;
    uint32_t nfat = CFSwapInt32BigToHost(fhdr->nfat_arch);

    const struct fat_arch *archs = (const struct fat_arch *)(bytes + sizeof(struct fat_header));

    for (uint32_t i = 0; i < nfat; i++) {
        uint32_t cputype = CFSwapInt32BigToHost(archs[i].cputype);
        if (cputype == CPU_TYPE_X86_64) {
            uint32_t offset = CFSwapInt32BigToHost(archs[i].offset);
            uint32_t size = CFSwapInt32BigToHost(archs[i].size);

            if (offset + size > length) {
                if (error) *error = [self error:[NSString stringWithFormat:@"%@: x86-64 slice exceeds input", name]];
                return nil;
            }

            return [data subdataWithRange:NSMakeRange(offset, size)];
        }
    }

    if (error) *error = [self error:[NSString stringWithFormat:@"%@: no x86-64 slice found", name]];
    return nil;
}

- (nullable NSNumber *)exportAddress:(NSString *)name loadBase:(uint64_t)loadBase error:(NSError **)error
{
    NSNumber *addr = self.exports[name];
    if (!addr) {
        if (error) *error = [self error:[NSString stringWithFormat:@"symbol %@ not found in %@", name, self.name]];
        return nil;
    }

    uint64_t symbolAddr = addr.unsignedLongLongValue;
    if (symbolAddr < self.base) {
        if (error) *error = [self error:[NSString stringWithFormat:@"symbol %@ in %@ precedes base", name, self.name]];
        return nil;
    }

    return @(loadBase + (symbolAddr - self.base));
}

- (void)relocate:(uint64_t)loadBase resolver:(uint64_t(^)(NSString *))resolver error:(NSError **)error
{
    if (self.relocated) {
        if (error) *error = [self error:[NSString stringWithFormat:@"%@ already relocated", self.name]];
        return;
    }

    for (NSDictionary *rebase in self.rebases) {
        NSString *segName = rebase[@"segment"];
        uint64_t offset = [rebase[@"offset"] unsignedLongLongValue];

        uint64_t fileOff = [self fileOffsetForSegment:segName offset:offset size:8 error:error];
        if (error && *error) return;

        uint64_t pointer = 0;
        memcpy(&pointer, self.data.bytes + fileOff, 8);
        uint64_t newAddr = loadBase + (pointer - self.base);

        uint8_t *mutable = (uint8_t *)self.data.mutableBytes;
        memcpy(mutable + fileOff, &newAddr, 8);
    }

    self.relocated = YES;
    self.loadedBase = loadBase;
}

- (uint64_t)fileOffsetForSegment:(NSString *)segName offset:(uint64_t)offset size:(uint64_t)size error:(NSError **)error
{
    for (NSDictionary *seg in self.segments) {
        if (![seg[@"name"] isEqualToString:segName]) continue;

        uint64_t segAddr = [seg[@"vmaddr"] unsignedLongLongValue];
        uint64_t segFileOff = [seg[@"fileoff"] unsignedLongLongValue];
        uint64_t segSize = [seg[@"vmsize"] unsignedLongLongValue];

        if (offset + size > segSize) {
            if (error) *error = [self error:[NSString stringWithFormat:@"fixup at 0x%llx exceeds segment %@ in %@", offset, segName, self.name]];
            return 0;
        }

        return segFileOff + offset;
    }

    if (error) *error = [self error:[NSString stringWithFormat:@"unknown segment %@ in %@", segName, self.name]];
    return 0;
}

- (void)loadImage:(WFSSAPMachOImage *)image error:(NSError **)error
{
    uint64_t span = 0;

    for (NSDictionary *seg in image.segments) {
        NSString *segName = seg[@"name"];
        if ([segName isEqualToString:@"__PAGEZERO"]) continue;

        uint64_t segAddr = [seg[@"vmaddr"] unsignedLongLongValue];
        uint64_t segSize = [seg[@"vmsize"] unsignedLongLongValue];
        if (segSize == 0) continue;

        uint64_t end = (segAddr - image.base) + segSize;
        if (end > span) span = end;
    }

    span = (span + kPageSize - 1) & ~(kPageSize - 1);
    if (span == 0) {
        if (error) *error = [self error:[NSString stringWithFormat:@"%@: no loadable segments", image.name]];
        return;
    }

    int rc = _unicorn.memMap(_engine, image.loadedBase, span, UC_PROT_ALL);
    if (rc != 0) {
        if (error) *error = [self error:[NSString stringWithFormat:@"memMap failed for %@: %s", image.name, _unicorn.strerror(rc)]];
        return;
    }

    for (NSDictionary *seg in image.segments) {
        NSString *segName = seg[@"name"];
        if ([segName isEqualToString:@"__PAGEZERO"]) continue;

        uint64_t fileSize = [seg[@"filesize"] unsignedLongLongValue];
        if (fileSize == 0) continue;

        uint64_t segAddr = [seg[@"vmaddr"] unsignedLongLongValue];
        uint64_t segFileOff = [seg[@"fileoff"] unsignedLongLongValue];
        uint64_t destAddr = image.loadedBase + (segAddr - image.base);

        rc = _unicorn.memWrite(_engine, destAddr, image.data.bytes + segFileOff, fileSize);
        if (rc != 0) {
            if (error) *error = [self error:[NSString stringWithFormat:@"memWrite failed for %@ segment %@: %s", image.name, segName, _unicorn.strerror(rc)]];
            return;
        }
    }
}

#pragma mark - Memory Helpers

- (void)mapRegions
{
    struct { uint64_t addr; uint64_t size; } regions[] = {
        {kReturnAddress, kPageSize},
        {kScratchBase, kScratchSize},
        {kHeapBase, kHeapSize},
        {kStackBase, kStackSize},
    };

    for (size_t i = 0; i < sizeof(regions)/sizeof(regions[0]); i++) {
        _unicorn.memMap(_engine, regions[i].addr, regions[i].size, UC_PROT_ALL);
    }
}

- (void)memWrite:(uint64_t)address data:(const void *)data size:(uint64_t)size
{
    _unicorn.memWrite(_engine, address, data, size);
}

- (NSData *)memRead:(uint64_t)address size:(uint64_t)size
{
    NSMutableData *data = [NSMutableData dataWithLength:size];
    _unicorn.memRead(_engine, address, data.mutableBytes, size);
    return data;
}

- (uint64_t)scratchReserve:(uint64_t)size
{
    uint64_t reserved = (size + 15) & ~15ULL;
    if (_scratchCursor + reserved > kScratchSize) return 0;
    uint64_t addr = kScratchBase + _scratchCursor;
    _scratchCursor += reserved;
    return addr;
}

- (uint64_t)scratchWrite:(const void *)data size:(uint64_t)size
{
    uint64_t addr = [self scratchReserve:size];
    if (addr && data && size) {
        _unicorn.memWrite(_engine, addr, data, size);
    } else if (addr && size) {
        void *zero = calloc(1, (size_t)size);
        _unicorn.memWrite(_engine, addr, zero, size);
        free(zero);
    }
    return addr;
}

- (uint64_t)scratchUint64Field
{
    return [self scratchReserve:8];
}

- (void)clearScratch
{
    if (_scratchCursor > 0) {
        void *zero = calloc(1, (size_t)_scratchCursor);
        _unicorn.memWrite(_engine, kScratchBase, zero, _scratchCursor);
        free(zero);
    }
    _scratchCursor = 0;
}

- (uint64_t)readUint64:(uint64_t)address
{
    uint64_t value = 0;
    _unicorn.memRead(_engine, address, &value, 8);
    return value;
}

- (uint32_t)readUint32:(uint64_t)address
{
    uint32_t value = 0;
    _unicorn.memRead(_engine, address, &value, 4);
    return value;
}

- (void)writeUint64:(uint64_t)address value:(uint64_t)value
{
    _unicorn.memWrite(_engine, address, &value, 8);
}

#pragma mark - Function Invocation

- (uint64_t)invoke:(uint64_t)function args:(uint64_t[])args count:(int)count
{
    if (_closed || function == 0) return 0;

    int regs[] = {
        UC_X86_REG_RDI,
        UC_X86_REG_RSI,
        UC_X86_REG_RDX,
        UC_X86_REG_RCX,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
    };

    int regCount = sizeof(regs) / sizeof(regs[0]);
    int stackArgs = count > regCount ? count - regCount : 0;

    uint64_t stackPtr = kStackBase + kStackSize - (stackArgs + 1) * 8;
    if (stackPtr % 16 != 8) stackPtr -= 8;

    [self writeUint64:stackPtr value:kReturnAddress];

    for (int i = 0; i < stackArgs; i++) {
        [self writeUint64:stackPtr + 8 + i * 8 value:args[regCount + i]];
    }

    for (int i = 0; i < regCount; i++) {
        uint64_t val = (i < count) ? args[i] : 0;
        _unicorn.regWrite(_engine, regs[i], &val);
    }

    _unicorn.regWrite(_engine, UC_X86_REG_RSP, &stackPtr);

    int rc = _unicorn.emuStart(_engine, function, kReturnAddress, kSAPGuestTimeout * 1000000ULL, 0);
    if (rc != 0) {
        return 0;
    }

    uint64_t rip = 0;
    _unicorn.regRead(_engine, UC_X86_REG_RIP, &rip);
    if (rip != kReturnAddress) return 0;

    uint64_t rax = 0;
    _unicorn.regRead(_engine, UC_X86_REG_RAX, &rax);
    return rax;
}

- (NSData *)consumeOutput:(uint64_t)pointerField lengthField:(uint64_t)lengthField
{
    uint64_t ptr = [self readUint64:pointerField];
    uint64_t len = [self readUint64:lengthField];

    if (len > kMaxOutputSize || ptr == 0) return nil;

    NSData *output = [self memRead:ptr size:len];

    _unicorn.memUnmap(_engine, ptr, (len + kPageSize - 1) & ~(kPageSize - 1));

    return output;
}

#pragma mark - Hardware ID

- (NSData *)hardwareBlock:(NSData *)hardwareID
{
    uint32_t len = (uint32_t)hardwareID.length;
    NSMutableData *block = [NSMutableData dataWithLength:24];
    [block replaceBytesInRange:NSMakeRange(0, 4) withBytes:&len];
    [block replaceBytesInRange:NSMakeRange(4, len) withBytes:hardwareID.bytes];
    return block;
}

#pragma mark - Public API

- (nullable NSNumber *)initializeWithHardwareID:(NSData *)hardwareID error:(NSError **)error
{
    _scratchCursor = 0;

    NSData *hwBlock = [self hardwareBlock:hardwareID];
    uint64_t contextField = [self scratchUint64Field];
    uint64_t hwAddr = [self scratchWrite:hwBlock.bytes size:hwBlock.length];

    uint64_t args[] = {contextField, hwAddr};
    uint64_t status = [self invoke:[_resolvedEntries[@"_cp2g1b9ro"] unsignedLongLongValue] args:args count:2];

    [self clearScratch];

    if ((int32_t)status != 0) {
        if (error) *error = [self error:[NSString stringWithFormat:@"SAP initialize returned %d", (int32_t)status]];
        return nil;
    }

    uint64_t ctx = [self readUint64:contextField];
    if (ctx == 0) {
        if (error) *error = [self error:@"SAP initialize returned null context"];
        return nil;
    }

    return @(ctx);
}

- (nullable NSDictionary *)exchangeWithVersion:(uint32_t)version
                                    hardwareID:(NSData *)hardwareID
                                       context:(uint64_t)context
                                         input:(NSData *)input
                                         error:(NSError **)error
{
    _scratchCursor = 0;

    NSData *hwBlock = [self hardwareBlock:hardwareID];
    uint64_t hwAddr = [self scratchWrite:hwBlock.bytes size:hwBlock.length];
    uint64_t inputAddr = [self scratchWrite:input.bytes size:input.length];
    uint64_t outputField = [self scratchUint64Field];
    uint64_t lengthField = [self scratchUint64Field];
    uint64_t resultField = [self scratchReserve:4];

    uint64_t args[] = {version, hwAddr, context, inputAddr, (uint64_t)input.length, outputField, lengthField, resultField};
    uint64_t status = [self invoke:[_resolvedEntries[@"_Mib5yocT"] unsignedLongLongValue] args:args count:8];

    if ((int32_t)status != 0) {
        [self clearScratch];
        if (error) *error = [self error:[NSString stringWithFormat:@"SAP exchange returned %d", (int32_t)status]];
        return nil;
    }

    NSData *output = [self consumeOutput:outputField lengthField:lengthField];
    uint32_t result = [self readUint32:resultField];

    [self clearScratch];

    return @{@"output": output ?: [NSData data], @"state": @(result)};
}

- (nullable NSData *)signWithContext:(uint64_t)context input:(NSData *)input error:(NSError **)error
{
    _scratchCursor = 0;

    uint64_t inputAddr = [self scratchWrite:input.bytes size:input.length];
    uint64_t outputField = [self scratchUint64Field];
    uint64_t lengthField = [self scratchUint64Field];

    uint64_t args[] = {context, inputAddr, (uint64_t)input.length, outputField, lengthField};
    uint64_t status = [self invoke:[_resolvedEntries[@"_Fc3vhtJDvr"] unsignedLongLongValue] args:args count:5];

    if ((int32_t)status != 0) {
        [self clearScratch];
        if (error) *error = [self error:[NSString stringWithFormat:@"SAP sign returned %d", (int32_t)status]];
        return nil;
    }

    NSData *output = [self consumeOutput:outputField lengthField:lengthField];

    [self clearScratch];

    if (!output.length) {
        if (error) *error = [self error:@"SAP sign returned empty signature"];
        return nil;
    }

    return output;
}

- (BOOL)teardownWithContext:(uint64_t)context error:(NSError **)error
{
    _scratchCursor = 0;

    uint64_t args[] = {context};
    uint64_t status = [self invoke:[_resolvedEntries[@"_IPaI1oem5iL"] unsignedLongLongValue] args:args count:1];

    [self clearScratch];

    if ((int32_t)status != 0) {
        if (error) *error = [self error:[NSString stringWithFormat:@"SAP teardown returned %d", (int32_t)status]];
        return NO;
    }

    return YES;
}

- (nullable NSString *)macAddress
{
    if (_shimMacAddress == 0) return nil;
    return @"02:00:00:00:00:00";
}

#pragma mark - Cleanup

- (void)close
{
    if (_closed) return;
    _closed = YES;

    if (_engine) {
        _unicorn.close(_engine);
        _engine = NULL;
    }

    wfs_unicorn_unload(&_unicorn);
}

- (void)dealloc
{
    [self close];
}

- (NSError *)error:(NSString *)message
{
    return [NSError errorWithDomain:@"WFSSAPMachine" code:-1 userInfo:@{NSLocalizedDescriptionKey: message}];
}

@end
