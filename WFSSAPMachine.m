#import "WFSSAPMachine.h"
#import "WFSSAPShims.h"
#import "WFSBridgingHeader.h"
#import "WaffleStore-Swift.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>

@interface WFSSAPMachine (MemHookInternal)
- (void)handleMemHookType:(int32_t)type address:(uint64_t)address size:(int)size;
@end

#ifndef INDIRECT_SYMBOL_ABS
#define INDIRECT_SYMBOL_ABS    0x40000000
#endif
#ifndef INDIRECT_SYMBOL_LOCAL
#define INDIRECT_SYMBOL_LOCAL  0x80000000
#endif

#ifndef REBASE_OPCODE_MASK
#define REBASE_OPCODE_MASK    0xF0
#define REBASE_OPCODE_DONE    0x00
#define REBASE_OPCODE_SET_TYPE_IMM  0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB  0x20
#define REBASE_OPCODE_ADD_SEGMENT_AND_OFFSET_ULEB  0x30
#define REBASE_OPCODE_ADD_ADDR_ULEB   0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES   0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES  0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB   0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80
#endif

#ifndef BIND_OPCODE_MASK
#define BIND_OPCODE_MASK   0xF0
#define BIND_OPCODE_DONE   0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM   0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB  0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM   0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM  0x40
#define BIND_OPCODE_SET_TYPE_IMM   0x50
#define BIND_OPCODE_SET_ADDEND_SLEB   0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB  0x70
#define BIND_OPCODE_ADD_ADDR_ULEB   0x80
#define BIND_OPCODE_DO_BIND   0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB   0xA0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB  0xC0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES   0xD0
#define BIND_OPCODE_THREADED   0xE0
#endif

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

static void shimCodeHookCallback(void *uc, uint64_t address, uint32_t size, void *user_data)
{
    (void)uc; (void)size;
    WFSSAPShims *shims = (__bridge WFSSAPShims *)user_data;
    if (shims) {
        [shims dispatchAtAddress:address];
    }
}

static const char *memTypeName(uint32_t type)
{
    switch (type) {
        case UC_MEM_READ:            return "READ";
        case UC_MEM_WRITE:           return "WRITE";
        case UC_MEM_FETCH:           return "FETCH";
        case UC_MEM_READ_UNMAPPED:   return "READ_UNMAPPED";
        case UC_MEM_WRITE_UNMAPPED:  return "WRITE_UNMAPPED";
        case UC_MEM_FETCH_UNMAPPED:  return "FETCH_UNMAPPED";
        case UC_MEM_READ_PROT:       return "READ_PROT";
        case UC_MEM_WRITE_PROT:      return "WRITE_PROT";
        case UC_MEM_FETCH_PROT:      return "FETCH_PROT";
        case UC_MEM_READ_AFTER:      return "READ_AFTER";
        default:                     return "UNKNOWN";
    }
}

static void machineMemHookCallback(void *uc, uint32_t type, uint64_t address, int size, int64_t value, void *user_data)
{
    (void)uc; (void)value;
    WFSSAPMachine *machine = (__bridge WFSSAPMachine *)user_data;
    if (machine) {
        [machine handleMemHookType:type address:address size:size];
    }
}

static BOOL wfsReadULEB(const uint8_t **cursor, const uint8_t *end, uint64_t *value)
{
    uint64_t result = 0;
    int shift = 0;
    const uint8_t *p = *cursor;
    while (p < end) {
        uint8_t byte = *p++;
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        if (!(byte & 0x80)) {
            *cursor = p;
            *value = result;
            return YES;
        }
        shift += 7;
        if (shift >= 64) return NO;
    }
    return NO;
}

static BOOL wfsReadSLEB(const uint8_t **cursor, const uint8_t *end, int64_t *value)
{
    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    const uint8_t *p = *cursor;
    while (p < end) {
        byte = *p++;
        result |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
        if (shift > 63) return NO;
    }
    if (shift < 64 && (byte & 0x40)) {
        result |= -((int64_t)1 << shift);
    }
    *cursor = p;
    *value = result;
    return YES;
}

#pragma mark - Bind Entry

@interface WFSSAPBindEntry : NSObject
@property (nonatomic, copy) NSString *symbol;
@property (nonatomic, copy) NSString *segment;
@property (nonatomic, assign) uint64_t segOffset;
@property (nonatomic, assign) int64_t addend;
@end

@implementation WFSSAPBindEntry
@end

#pragma mark - Mach-O Image

@interface WFSSAPMachOImage : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, strong) NSMutableData *data;
@property (nonatomic, assign) uint64_t base;
@property (nonatomic, strong) NSArray<NSDictionary *> *segments;
@property (nonatomic, strong) NSArray<NSDictionary *> *rebases;
@property (nonatomic, strong) NSArray<WFSSAPBindEntry *> *binds;
@property (nonatomic, strong) NSDictionary<NSString *, NSNumber *> *exports;
@property (nonatomic, assign) BOOL relocated;
@property (nonatomic, assign) uint64_t loadedBase;
@property (nonatomic, assign) uint64_t linkeditFileOff;
@property (nonatomic, assign) uint32_t rebaseOff;
@property (nonatomic, assign) uint32_t rebaseSize;
@property (nonatomic, assign) uint32_t bindOff;
@property (nonatomic, assign) uint32_t bindSize;
@property (nonatomic, assign) uint32_t lazyBindOff;
@property (nonatomic, assign) uint32_t lazyBindSize;
@property (nonatomic, assign) BOOL hasDyldInfo;
- (nullable instancetype)initWithName:(NSString *)name data:(NSData *)data error:(NSError **)error;
- (nullable NSNumber *)exportAddress:(NSString *)symbolName loadBase:(uint64_t)loadBase error:(NSError **)error;
- (void)relocate:(uint64_t)loadBase resolver:(uint64_t(^)(NSString *))resolver error:(NSError **)error;
- (void)loadIntoEngine:(WFSSwiftUnicorn *)api engine:(void *)engine error:(NSError **)error;
@end

@implementation WFSSAPMachOImage

- (nullable instancetype)initWithName:(NSString *)name data:(NSData *)rawData error:(NSError **)error
{
    self = [super init];
    if (!self) return nil;

    _name = [name copy];

    const uint8_t *bytes = rawData.bytes;
    NSUInteger length = rawData.length;

    if (length < sizeof(uint32_t)) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: data too short", name]];
        return nil;
    }

    uint32_t magic = *(const uint32_t *)bytes;
    NSData *sliceData = rawData;

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        sliceData = [self extractX86_64Slice:rawData name:name error:error];
        if (!sliceData) return nil;
        bytes = sliceData.bytes;
        length = sliceData.length;
        magic = *(const uint32_t *)bytes;
    }

    if (magic != MH_MAGIC_64) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: not x86-64 (magic=0x%x)", name, magic]];
        return nil;
    }

    _data = [sliceData mutableCopy] ?: [[NSMutableData alloc] initWithData:sliceData];

    const struct mach_header_64 *hdr = (const struct mach_header_64 *)bytes;
    _base = hdr->reserved;

    NSMutableArray *segments = [NSMutableArray array];
    NSMutableArray *rebases = [NSMutableArray array];
    NSMutableArray *binds = [NSMutableArray array];
    NSMutableDictionary *exports = [NSMutableDictionary dictionary];

    const struct symtab_command *symtabCmd = NULL;
    const struct dysymtab_command *dysymtabCmd = NULL;
    const struct load_command *cmd = (const struct load_command *)(bytes + sizeof(struct mach_header_64));

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;

            [segments addObject:@{
                @"name": @(seg->segname),
                @"vmaddr": @(seg->vmaddr),
                @"vmsize": @(seg->vmsize),
                @"fileoff": @(seg->fileoff),
                @"filesize": @(seg->filesize),
            }];

            if (strncmp(seg->segname, "__LINKEDIT", 10) == 0) {
                _linkeditFileOff = seg->fileoff;
            }

            const struct section_64 *sec = (const struct section_64 *)((const uint8_t *)cmd + sizeof(struct segment_command_64));
            uint32_t nsects = (seg->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64);

            for (uint32_t j = 0; j < nsects; j++) {
                uint32_t secType = sec[j].flags & SECTION_TYPE;
                if (secType == S_LAZY_SYMBOL_POINTERS || secType == S_NON_LAZY_SYMBOL_POINTERS) {
                    uint64_t secAddr = sec[j].addr;
                    uint64_t secSize = sec[j].size;
                    uint64_t secOff = sec[j].offset;
                    uint32_t indirectIndex = sec[j].reserved1;
                    uint64_t ptrCount = secSize / 8;
                    for (uint64_t k = 0; k < ptrCount; k++) {
                        [rebases addObject:@{
                            @"segment": @(seg->segname),
                            @"offset": @(secAddr - seg->vmaddr + k * 8),
                            @"fileOffset": @(secOff + k * 8),
                            @"indirectIndex": @(indirectIndex + (uint32_t)k),
                        }];
                    }
                }
            }
        }

        if (cmd->cmd == LC_SYMTAB) {
            symtabCmd = (const struct symtab_command *)cmd;
        }

        if (cmd->cmd == LC_DYSYMTAB) {
            dysymtabCmd = (const struct dysymtab_command *)cmd;
        }

        if (cmd->cmd == LC_DYLD_INFO || cmd->cmd == LC_DYLD_INFO_ONLY) {
            const struct dyld_info_command *dyldInfo = (const struct dyld_info_command *)cmd;
            _hasDyldInfo = YES;
            _rebaseOff = dyldInfo->rebase_off;
            _rebaseSize = dyldInfo->rebase_size;
            _bindOff = dyldInfo->bind_off;
            _bindSize = dyldInfo->bind_size;
            _lazyBindOff = dyldInfo->lazy_bind_off;
            _lazyBindSize = dyldInfo->lazy_bind_size;
        }

        cmd = (const struct load_command *)((const uint8_t *)cmd + cmd->cmdsize);
    }

    if (symtabCmd && symtabCmd->symoff > 0 && symtabCmd->stroff > 0) {
        const uint8_t *strtab = bytes + symtabCmd->stroff;
        const struct nlist_64 *syms = (const struct nlist_64 *)(bytes + symtabCmd->symoff);

        for (uint32_t j = 0; j < symtabCmd->nsyms; j++) {
            if (syms[j].n_value == 0) continue;
            if (syms[j].n_type & N_STAB) continue;
            const char *symName = (const char *)(strtab + syms[j].n_un.n_strx);
            if (!symName || symName[0] != '_') continue;
            exports[@(symName)] = @(syms[j].n_value);
        }

        if (!_hasDyldInfo && dysymtabCmd && dysymtabCmd->nindirectsyms > 0 && dysymtabCmd->indirectsymoff > 0) {
            const uint32_t *indirectSyms = (const uint32_t *)(bytes + dysymtabCmd->indirectsymoff);

            for (NSDictionary *rebase in rebases) {
                uint32_t indirectIdx = [rebase[@"indirectIndex"] unsignedIntValue];
                if (indirectIdx >= dysymtabCmd->nindirectsyms) continue;

                uint32_t symIdx = indirectSyms[indirectIdx];
                if (symIdx & INDIRECT_SYMBOL_ABS || symIdx & INDIRECT_SYMBOL_LOCAL) continue;
                if (symIdx >= symtabCmd->nsyms) continue;

                const char *symName = (const char *)(strtab + syms[symIdx].n_un.n_strx);
                if (!symName || symName[0] != '_') continue;

                if (exports[@(symName)]) continue;

                WFSSAPBindEntry *bind = [WFSSAPBindEntry new];
                bind.symbol = @(symName);
                bind.segment = rebase[@"segment"];
                bind.segOffset = [rebase[@"offset"] unsignedLongLongValue];
                bind.addend = 0;
                [binds addObject:bind];
            }
        }
    }

    for (NSDictionary *seg in segments) {
        if ([seg[@"name"] isEqualToString:@"__TEXT"]) {
            _base = [seg[@"vmaddr"] unsignedLongLongValue];
            break;
        }
    }

    _segments = segments;
    _exports = exports;

    if (_hasDyldInfo) {
        NSMutableArray *dyldRebases = [NSMutableArray array];
        NSMutableArray *dyldBinds = [NSMutableArray array];
        if (![self parseDyldInfo:bytes rebases:dyldRebases binds:dyldBinds error:error]) {
            return nil;
        }
        rebases = dyldRebases;
        binds = dyldBinds;
    }

    _rebases = rebases;
    _binds = binds;

    return self;
}

- (BOOL)parseDyldInfo:(const uint8_t *)bytes rebases:(NSMutableArray *)outRebases binds:(NSMutableArray *)outBinds error:(NSError **)error
{
    if (_linkeditFileOff == 0) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: LC_DYLD_INFO present but no __LINKEDIT", _name]];
        return NO;
    }

    const uint8_t *streamBase = bytes + _linkeditFileOff;

    if (_rebaseSize > 0) {
        if (![self parseRebaseStream:streamBase + _rebaseOff size:_rebaseSize into:outRebases error:error]) {
            return NO;
        }
    }

    if (_bindSize > 0) {
        if (![self parseBindStream:streamBase + _bindOff size:_bindSize into:outBinds error:error]) {
            return NO;
        }
    }

    if (_lazyBindSize > 0) {
        if (![self parseBindStream:streamBase + _lazyBindOff size:_lazyBindSize into:outBinds error:error]) {
            return NO;
        }
    }

    return YES;
}

- (BOOL)parseRebaseStream:(const uint8_t *)stream size:(uint32_t)size into:(NSMutableArray *)outRebases error:(NSError **)error
{
    const uint8_t *p = stream;
    const uint8_t *end = stream + size;
    int segIndex = -1;
    uint64_t offset = 0;
    uint32_t type = REBASE_TYPE_POINTER;

    while (p < end) {
        uint8_t opcodeByte = *p++;
        uint8_t opcode = opcodeByte & REBASE_OPCODE_MASK;

        switch (opcode) {
            case REBASE_OPCODE_DONE:
                return YES;

            case REBASE_OPCODE_SET_TYPE_IMM:
                type = opcodeByte & 0x0F;
                break;

            case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
                uint64_t u = 0;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                segIndex = opcodeByte & 0x0F;
                offset = u;
                break;
            }

            case REBASE_OPCODE_ADD_SEGMENT_AND_OFFSET_ULEB: {
                uint64_t u = 0;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                segIndex = opcodeByte & 0x0F;
                offset += u;
                break;
            }

            case REBASE_OPCODE_ADD_ADDR_ULEB: {
                uint64_t u = 0;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                offset += u;
                break;
            }

            case REBASE_OPCODE_DO_REBASE_IMM_TIMES: {
                if (![self addRebaseType:type count:opcodeByte & 0x0F segmentIndex:segIndex offset:&offset into:outRebases error:error]) return NO;
                break;
            }

            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
                uint64_t count = 0;
                if (!wfsReadULEB(&p, end, &count)) goto malformed;
                if (![self addRebaseType:type count:count segmentIndex:segIndex offset:&offset into:outRebases error:error]) return NO;
                break;
            }

            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
                uint64_t u = 0;
                if (![self addRebaseType:type count:1 segmentIndex:segIndex offset:&offset into:outRebases error:error]) return NO;
                offset += 8;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                offset += u;
                break;
            }

            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = 0, skip = 0;
                if (!wfsReadULEB(&p, end, &count)) goto malformed;
                if (!wfsReadULEB(&p, end, &skip)) goto malformed;
                if (![self addRebaseType:type count:count segmentIndex:segIndex offset:&offset skip:skip into:outRebases error:error]) return NO;
                break;
            }

            default:
                if (error) *error = [self err:[NSString stringWithFormat:@"%@: unsupported rebase opcode 0x%02x", _name, opcode]];
                return NO;
        }
    }

malformed:
    if (error) *error = [self err:[NSString stringWithFormat:@"%@: malformed rebase stream", _name]];
    return NO;
}

- (BOOL)addRebaseType:(uint32_t)type count:(uint64_t)count segmentIndex:(int)segIndex offset:(uint64_t *)offset skip:(uint64_t)skip into:(NSMutableArray *)outRebases error:(NSError **)error
{
    while (count-- > 0) {
        if (![self addRebaseType:type count:1 segmentIndex:segIndex offset:offset into:outRebases error:error]) return NO;
        *offset += skip;
    }
    return YES;
}

- (BOOL)addRebaseType:(uint32_t)type count:(uint64_t)count segmentIndex:(int)segIndex offset:(uint64_t *)offset into:(NSMutableArray *)outRebases error:(NSError **)error
{
    if (segIndex < 0 || segIndex >= (int)_segments.count) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: rebase segment index %d out of range", _name, segIndex]];
        return NO;
    }
    if (type != REBASE_TYPE_POINTER) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: unsupported rebase type %u", _name, type]];
        return NO;
    }

    NSString *segName = _segments[(NSUInteger)segIndex][@"name"];
    for (uint64_t i = 0; i < count; i++) {
        [outRebases addObject:@{
            @"segment": segName,
            @"offset": @(*offset + i * 8),
            @"type": @(type),
        }];
    }
    *offset += 8 * count;
    return YES;
}

- (BOOL)parseBindStream:(const uint8_t *)stream size:(uint32_t)size into:(NSMutableArray *)outBinds error:(NSError **)error
{
    const uint8_t *p = stream;
    const uint8_t *end = stream + size;
    int segIndex = -1;
    uint64_t offset = 0;
    int64_t addend = 0;
    NSString *symbol = nil;

    while (p < end) {
        uint8_t opcodeByte = *p++;
        uint8_t opcode = opcodeByte & BIND_OPCODE_MASK;

        switch (opcode) {
            case BIND_OPCODE_DONE:
                return YES;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
                uint64_t u = 0;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                break;
            }

            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                const uint8_t *symBegin = p;
                while (p < end && *p) p++;
                if (p >= end) goto malformed;
                symbol = [[NSString alloc] initWithBytes:symBegin length:(NSUInteger)(p - symBegin) encoding:NSUTF8StringEncoding];
                p++;
                break;
            }

            case BIND_OPCODE_SET_TYPE_IMM:
                break;

            case BIND_OPCODE_SET_ADDEND_SLEB: {
                if (!wfsReadSLEB(&p, end, &addend)) goto malformed;
                break;
            }

            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
                uint64_t u = 0;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                segIndex = opcodeByte & 0x0F;
                offset = u;
                break;
            }

            case BIND_OPCODE_ADD_ADDR_ULEB: {
                uint64_t u = 0;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                offset += u;
                break;
            }

            case BIND_OPCODE_DO_BIND: {
                if (![self addBindSymbol:symbol segmentIndex:segIndex offset:offset addend:addend into:outBinds error:error]) return NO;
                offset += 8;
                break;
            }

            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                uint64_t u = 0;
                if (![self addBindSymbol:symbol segmentIndex:segIndex offset:offset addend:addend into:outBinds error:error]) return NO;
                offset += 8;
                if (!wfsReadULEB(&p, end, &u)) goto malformed;
                offset += u;
                break;
            }

            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = 0, skip = 0;
                if (!wfsReadULEB(&p, end, &count)) goto malformed;
                if (!wfsReadULEB(&p, end, &skip)) goto malformed;
                for (uint64_t i = 0; i < count; i++) {
                    if (![self addBindSymbol:symbol segmentIndex:segIndex offset:offset addend:addend into:outBinds error:error]) return NO;
                    offset += 8 + skip;
                }
                break;
            }

            case BIND_OPCODE_DO_BIND_ULEB_TIMES: {
                uint64_t count = 0;
                if (!wfsReadULEB(&p, end, &count)) goto malformed;
                for (uint64_t i = 0; i < count; i++) {
                    if (![self addBindSymbol:symbol segmentIndex:segIndex offset:offset addend:addend into:outBinds error:error]) return NO;
                    offset += 8;
                }
                break;
            }

            case BIND_OPCODE_THREADED:
                if (error) *error = [self err:[NSString stringWithFormat:@"%@: threaded bind fixups unsupported", _name]];
                return NO;

            default:
                if (error) *error = [self err:[NSString stringWithFormat:@"%@: unsupported bind opcode 0x%02x", _name, opcode]];
                return NO;
        }
    }

malformed:
    if (error) *error = [self err:[NSString stringWithFormat:@"%@: malformed bind stream", _name]];
    return NO;
}

- (BOOL)addBindSymbol:(NSString *)symbol segmentIndex:(int)segIndex offset:(uint64_t)offset addend:(int64_t)addend into:(NSMutableArray *)outBinds error:(NSError **)error
{
    if (!symbol.length) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: bind with empty symbol", _name]];
        return NO;
    }
    if (segIndex < 0 || segIndex >= (int)_segments.count) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: bind segment index %d out of range", _name, segIndex]];
        return NO;
    }

    WFSSAPBindEntry *bind = [WFSSAPBindEntry new];
    bind.symbol = symbol;
    bind.segment = _segments[(NSUInteger)segIndex][@"name"];
    bind.segOffset = offset;
    bind.addend = addend;
    [outBinds addObject:bind];
    return YES;
}

- (nullable NSNumber *)exportAddress:(NSString *)symbolName loadBase:(uint64_t)loadBase error:(NSError **)error
{
    NSNumber *addr = _exports[symbolName];
    if (!addr) {
        if (error) *error = [self err:[NSString stringWithFormat:@"symbol %@ not found in %@", symbolName, _name]];
        return nil;
    }
    uint64_t symbolAddr = addr.unsignedLongLongValue;
    if (symbolAddr < _base) {
        if (error) *error = [self err:[NSString stringWithFormat:@"symbol %@ precedes base in %@", symbolName, _name]];
        return nil;
    }
    return @(loadBase + (symbolAddr - _base));
}

- (void)relocate:(uint64_t)loadBase resolver:(uint64_t(^)(NSString *))resolver error:(NSError **)error
{
    if (_relocated) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@ already relocated", _name]];
        return;
    }

    for (NSDictionary *rebase in _rebases) {
        NSString *segName = rebase[@"segment"];
        uint64_t offset = [rebase[@"offset"] unsignedLongLongValue];
        uint64_t fileOff = [self fileOffsetForSegment:segName offset:offset size:8 error:error];
        if (error && *error) return;

        uint64_t pointer = 0;
        memcpy(&pointer, _data.bytes + fileOff, 8);
        uint64_t newAddr = loadBase + (pointer - _base);

        uint8_t *mutable = (uint8_t *)_data.mutableBytes;
        memcpy(mutable + fileOff, &newAddr, 8);
    }

    for (WFSSAPBindEntry *bind in _binds) {
        uint64_t fileOff = [self fileOffsetForSegment:bind.segment offset:bind.segOffset size:8 error:error];
        if (error && *error) return;

        uint64_t resolved = resolver(bind.symbol);
        if (resolved == 0) {
            if (error) *error = [self err:[NSString stringWithFormat:@"unresolved bind symbol %@ in %@", bind.symbol, _name]];
            return;
        }

        int64_t addend = bind.addend;
        uint64_t finalAddr;
        if (addend >= 0) {
            finalAddr = resolved + (uint64_t)addend;
        } else {
            uint64_t magnitude = (uint64_t)(-(addend + 1)) + 1;
            finalAddr = resolved - magnitude;
        }

        uint8_t *mutable = (uint8_t *)_data.mutableBytes;
        memcpy(mutable + fileOff, &finalAddr, 8);
    }

    _relocated = YES;
    _loadedBase = loadBase;
}

- (void)loadIntoEngine:(WFSSwiftUnicorn *)api engine:(void *)engine error:(NSError **)error
{
    if (!_relocated) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@ must be relocated first", _name]];
        return;
    }

    uint64_t span = 0;
    for (NSDictionary *seg in _segments) {
        if ([seg[@"name"] isEqualToString:@"__PAGEZERO"]) continue;
        uint64_t segSize = [seg[@"vmsize"] unsignedLongLongValue];
        if (segSize == 0) continue;
        uint64_t segAddr = [seg[@"vmaddr"] unsignedLongLongValue];
        uint64_t end = (segAddr - _base) + segSize;
        if (end > span) span = end;
    }

    span = (span + kPageSize - 1) & ~(kPageSize - 1);
    if (span == 0) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: no loadable segments", _name]];
        return;
    }

    int rc = [api memMap:_loadedBase size:span perms:UC_PROT_ALL];
    if (rc != 0) {
        if (error) *error = [self err:[NSString stringWithFormat:@"memMap %@ failed: %s", _name, [[api strerror:rc] UTF8String]]];
        return;
    }

    for (NSDictionary *seg in _segments) {
        if ([seg[@"name"] isEqualToString:@"__PAGEZERO"]) continue;
        uint64_t fileSize = [seg[@"filesize"] unsignedLongLongValue];
        if (fileSize == 0) continue;
        uint64_t segAddr = [seg[@"vmaddr"] unsignedLongLongValue];
        uint64_t segFileOff = [seg[@"fileoff"] unsignedLongLongValue];
        uint64_t destAddr = _loadedBase + (segAddr - _base);

        rc = [api memWrite:destAddr data:_data.bytes + segFileOff size:fileSize];
        if (rc != 0) {
            if (error) *error = [self err:[NSString stringWithFormat:@"memWrite %@ seg %@: %s", _name, seg[@"name"], [[api strerror:rc] UTF8String]]];
            return;
        }
    }
}

#pragma mark - Helpers

- (uint64_t)fileOffsetForSegment:(NSString *)segName offset:(uint64_t)offset size:(uint64_t)size error:(NSError **)error
{
    for (NSDictionary *seg in _segments) {
        if (![seg[@"name"] isEqualToString:segName]) continue;
        uint64_t segFileOff = [seg[@"fileoff"] unsignedLongLongValue];
        uint64_t segSize = [seg[@"vmsize"] unsignedLongLongValue];
        if (offset + size > segSize) {
            if (error) *error = [self err:[NSString stringWithFormat:@"fixup 0x%llx exceeds seg %@ in %@", offset, segName, _name]];
            return 0;
        }
        return segFileOff + offset;
    }
    if (error) *error = [self err:[NSString stringWithFormat:@"unknown segment %@ in %@", segName, _name]];
    return 0;
}

- (nullable NSData *)extractX86_64Slice:(NSData *)data name:(NSString *)name error:(NSError **)error
{
    const uint8_t *bytes = data.bytes;
    if (data.length < sizeof(struct fat_header)) {
        if (error) *error = [self err:[NSString stringWithFormat:@"%@: fat header too short", name]];
        return nil;
    }
    const struct fat_header *fhdr = (const struct fat_header *)bytes;
    uint32_t nfat = CFSwapInt32BigToHost(fhdr->nfat_arch);
    const struct fat_arch *archs = (const struct fat_arch *)(bytes + sizeof(struct fat_header));

    for (uint32_t i = 0; i < nfat; i++) {
        if (CFSwapInt32BigToHost(archs[i].cputype) == CPU_TYPE_X86_64) {
            uint32_t offset = CFSwapInt32BigToHost(archs[i].offset);
            uint32_t size = CFSwapInt32BigToHost(archs[i].size);
            if (offset + size > data.length) {
                if (error) *error = [self err:[NSString stringWithFormat:@"%@: x86-64 slice exceeds input", name]];
                return nil;
            }
            return [data subdataWithRange:NSMakeRange(offset, size)];
        }
    }
    if (error) *error = [self err:[NSString stringWithFormat:@"%@: no x86-64 slice", name]];
    return nil;
}

- (NSError *)err:(NSString *)msg
{
    return [NSError errorWithDomain:@"WFSSAPMachO" code:-1 userInfo:@{NSLocalizedDescriptionKey: msg}];
}

@end

#pragma mark - Machine

@interface WFSSAPMachine ()
@property (nonatomic, strong) WFSSwiftUnicorn *unicorn;
@property (nonatomic, assign) void *engine;
@property (nonatomic, strong) WFSSAPMachOImage *coreFPImage;
@property (nonatomic, strong) WFSSAPMachOImage *commerceCoreImage;
@property (nonatomic, strong) WFSSAPMachOImage *commerceKitImage;
@property (nonatomic, strong) WFSSAPShims *shims;
@property (nonatomic, strong) NSDictionary<NSString *, NSNumber *> *resolvedEntries;
@property (nonatomic, assign) uint64_t scratchCursor;
@property (nonatomic, assign) BOOL closed;
@property (nonatomic, assign) uint64_t codeHook;
@property (nonatomic, assign) uint64_t memHook;
@property (nonatomic, copy, nullable) NSString *memFault;
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

    WFSSwiftUnicorn *unicorn = [WFSSwiftUnicorn create];
    if (!unicorn || ![unicorn isLoaded]) {
        NSString *detail = unicorn.loadError.length ? unicorn.loadError : @"libunicorn.dylib not found";
        if (error) *error = [self machineError:[NSString stringWithFormat:@"Failed to load Unicorn: %@", detail]];
        return nil;
    }
    _unicorn = unicorn;

    int rc = [_unicorn openArch:UC_ARCH_X86 mode:UC_MODE_64];
    if (rc != 0) {
        if (error) *error = [self machineError:[NSString stringWithFormat:@"uc_open: %s", [[_unicorn strerror:rc] UTF8String]]];
        return nil;
    }
    _engine = [_unicorn engine];

    NSLog(@"WFSSAPMachine: Unicorn %@", [_unicorn libraryVersion]);

    BOOL ready = NO;
    @try {
        _coreFPImage = [[WFSSAPMachOImage alloc] initWithName:@"CoreFP" data:coreFPData error:error];
        if (!_coreFPImage) return nil;

        _commerceCoreImage = [[WFSSAPMachOImage alloc] initWithName:@"CommerceCore" data:commerceCoreData error:error];
        if (!_commerceCoreImage) return nil;

        _commerceKitImage = [[WFSSAPMachOImage alloc] initWithName:@"CommerceKit" data:commerceKitData error:error];
        if (!_commerceKitImage) return nil;

        NSMutableDictionary *allExports = [NSMutableDictionary dictionary];
        NSMutableDictionary *entries = [NSMutableDictionary dictionary];

        for (NSString *name in [NSArray arrayWithObjects:kCoreFPExportNames count:sizeof(kCoreFPExportNames)/sizeof(kCoreFPExportNames[0])]) {
            NSNumber *addr = [_coreFPImage exportAddress:name loadBase:kCoreFPBase error:error];
            if (!addr) return nil;
            allExports[name] = addr;
        }

        {
            NSNumber *addr = [_commerceCoreImage exportAddress:@"_get_mac_address" loadBase:kCommerceBase error:error];
            if (!addr) return nil;
            allExports[@"_get_mac_address"] = addr;
        }

        for (NSString *name in [NSArray arrayWithObjects:kEntryNames count:sizeof(kEntryNames)/sizeof(kEntryNames[0])]) {
            NSNumber *addr = [_commerceKitImage exportAddress:name loadBase:kKitBase error:error];
            if (!addr) return nil;
            allExports[name] = addr;
            entries[name] = addr;
        }
        _resolvedEntries = entries;

        {
            int memRc = [self mapMemory];
            if (memRc != 0) {
                if (error) *error = [self machineError:[NSString stringWithFormat:@"memory map failed: %s", [[_unicorn strerror:memRc] UTF8String]]];
                return nil;
            }
        }

        uint8_t hlt = 0xF4;
        {
            int rcHlt = [_unicorn memWrite:kReturnAddress data:&hlt size:1];
            if (rcHlt != 0) {
                if (error) *error = [self machineError:[NSString stringWithFormat:@"memWrite return address failed: %s", [[_unicorn strerror:rcHlt] UTF8String]]];
                return nil;
            }
        }

        NSError *shimError = nil;
        _shims = [[WFSSAPShims alloc] initWithEngine:_engine api:_unicorn coreExports:allExports icxs:coreFPICXS error:&shimError];
        if (!_shims) {
            if (error) *error = shimError;
            return nil;
        }

        {
            int hookRc = [_unicorn hookAdd:UC_HOOK_CODE callback:(void *)shimCodeHookCallback userData:(uint64_t)(__bridge void *)_shims begin:0x0000200000000000ULL end:0x0000200000080000ULL];
            if (hookRc != 0) {
                if (error) *error = [self machineError:[NSString stringWithFormat:@"hookAdd failed: %s", [[_unicorn strerror:hookRc] UTF8String]]];
                return nil;
            }
            _codeHook = _unicorn.lastHook;
            if (_codeHook == 0) {
                if (error) *error = [self machineError:@"hookAdd returned no hook handle"];
                return nil;
            }
        }

        {
            int memHookType = UC_HOOK_MEM_READ_UNMAPPED
                            | UC_HOOK_MEM_WRITE_UNMAPPED
                            | UC_HOOK_MEM_FETCH_UNMAPPED
                            | UC_HOOK_MEM_READ_PROT
                            | UC_HOOK_MEM_WRITE_PROT
                            | UC_HOOK_MEM_FETCH_PROT;
            int memHookRc = [_unicorn hookAdd:memHookType callback:(void *)machineMemHookCallback userData:(uint64_t)(__bridge void *)self begin:0 end:0];
            if (memHookRc != 0) {
                if (error) *error = [self machineError:[NSString stringWithFormat:@"memHookAdd failed: %s", [[_unicorn strerror:memHookRc] UTF8String]]];
                return nil;
            }
            _memHook = _unicorn.lastHook;
            if (_memHook == 0) {
                if (error) *error = [self machineError:@"memHookAdd returned no hook handle"];
                return nil;
            }
        }

        uint64_t(^resolver)(NSString *) = ^uint64_t(NSString *n) {
            NSNumber *a = allExports[n];
            if (a) return a.unsignedLongLongValue;

            NSError *resolveErr = nil;
            uint64_t shimAddr = [self->_shims resolveSymbol:n error:&resolveErr];
            if (shimAddr != 0) return shimAddr;

            return 0;
        };

        [_coreFPImage relocate:kCoreFPBase resolver:resolver error:error];
        if (error && *error) return nil;

        [_commerceCoreImage relocate:kCommerceBase resolver:resolver error:error];
        if (error && *error) return nil;

        [_commerceKitImage relocate:kKitBase resolver:resolver error:error];
        if (error && *error) return nil;

        [_coreFPImage loadIntoEngine:_unicorn engine:_engine error:error];
        if (error && *error) return nil;
        [_commerceCoreImage loadIntoEngine:_unicorn engine:_engine error:error];
        if (error && *error) return nil;
        [_commerceKitImage loadIntoEngine:_unicorn engine:_engine error:error];
        if (error && *error) return nil;

        ready = YES;
    } @finally {
        if (!ready) [self close];
    }

    return self;
}

#pragma mark - Memory

- (int)mapMemory
{
    struct { uint64_t addr; uint64_t size; } regions[] = {
        {kReturnAddress, kPageSize},
        {kScratchBase, kScratchSize},
        {kHeapBase, kHeapSize},
        {kStackBase, kStackSize},
    };
    for (size_t i = 0; i < sizeof(regions)/sizeof(regions[0]); i++) {
        int rc = [_unicorn memMap:regions[i].addr size:regions[i].size perms:UC_PROT_ALL];
        if (rc != 0) {
            NSLog(@"WFSSAPMachine: memMap 0x%llx/0x%llx failed: %@", regions[i].addr, regions[i].size, [_unicorn strerror:rc]);
            return rc;
        }
    }
    return 0;
}

- (uint64_t)scratchReserve:(uint64_t)size
{
    uint64_t reserved = (size + 15) & ~15ULL;
    if (_scratchCursor + reserved > kScratchSize) return 0;
    uint64_t addr = kScratchBase + _scratchCursor;
    _scratchCursor += reserved;
    if (size > 0) {
        void *zero = calloc(1, (size_t)reserved);
        [_unicorn memWrite:addr data:zero size:reserved];
        free(zero);
    }
    return addr;
}

- (uint64_t)scratchWrite:(const void *)data size:(uint64_t)size
{
    uint64_t addr = [self scratchReserve:size];
    if (addr && data && size) [_unicorn memWrite:addr data:data size:size];
    return addr;
}

- (uint64_t)readUint64:(uint64_t)address
{
    uint64_t v = 0;
    [_unicorn memRead:address buffer:&v size:8];
    return v;
}

- (uint32_t)readUint32:(uint64_t)address
{
    uint32_t v = 0;
    [_unicorn memRead:address buffer:&v size:4];
    return v;
}

- (void)writeUint64:(uint64_t)address value:(uint64_t)value
{
    [_unicorn memWrite:address data:&value size:8];
}

- (NSData *)consumeOutput:(uint64_t)ptrField lengthField:(uint64_t)lenField
{
    uint64_t ptr = [self readUint64:ptrField];
    uint64_t len = [self readUint64:lenField];
    if (len > kMaxOutputSize || ptr == 0) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:len];
    [_unicorn memRead:ptr buffer:out.mutableBytes size:len];
    return out;
}

#pragma mark - Invocation

- (void)handleMemHookType:(int32_t)type address:(uint64_t)address size:(int)size
{
    uint64_t rip = [_unicorn regReadU64:UC_X86_REG_RIP];
    NSString *desc = [NSString stringWithFormat:@"memory violation %s at 0x%llx size=%d (RIP=0x%llx)",
                      memTypeName((uint32_t)type), address, size, rip];
    self.memFault = desc;
    NSLog(@"WFSSAPMachine: %@", desc);
    [_unicorn emuStop];
}

- (uint64_t)invoke:(uint64_t)function args:(uint64_t[])args count:(int)count
{
    if (_closed || function == 0) return 0;

    [_shims resetFault];

    int regs[] = {UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9};
    int regCount = 6;
    int stackArgs = count > regCount ? count - regCount : 0;

    uint64_t stackPtr = kStackBase + kStackSize - (stackArgs + 1) * 8;
    if (stackPtr % 16 != 8) stackPtr -= 8;

    [self writeUint64:stackPtr value:kReturnAddress];
    for (int i = 0; i < stackArgs; i++) {
        [self writeUint64:stackPtr + 8 + i * 8 value:args[regCount + i]];
    }
    for (int i = 0; i < regCount; i++) {
        uint64_t val = (i < count) ? args[i] : 0;
        [_unicorn regWriteU64:regs[i] :val];
    }
    [_unicorn regWriteU64:UC_X86_REG_RSP :stackPtr];

    int rc = [_unicorn emuStart:function until:kReturnAddress timeout:kSAPGuestTimeout * 1000000ULL count:0];
    if (rc != 0) {
        NSLog(@"WFSSAPMachine: uc_emu_start(0x%llx) failed: %@", function, [_unicorn strerror:rc]);
        return 0;
    }

    if (_shims.faulted) {
        NSLog(@"WFSSAPMachine: shim fault during 0x%llx: %@", function, _shims.fault.localizedDescription ?: @"?");
        return 0;
    }

    if (self.memFault) {
        NSLog(@"WFSSAPMachine: %@ during 0x%llx", self.memFault, function);
        self.memFault = nil;
        return 0;
    }

    uint64_t rip = [_unicorn regReadU64:UC_X86_REG_RIP];
    if (rip != kReturnAddress) {
        NSLog(@"WFSSAPMachine: execution stopped at 0x%llx, expected kReturnAddress", rip);
        return 0;
    }

    uint64_t rax = [_unicorn regReadU64:UC_X86_REG_RAX];
    return rax;
}

- (NSData *)hardwareBlock:(NSData *)hw
{
    uint32_t len = (uint32_t)hw.length;
    NSMutableData *block = [NSMutableData dataWithLength:24];
    [block replaceBytesInRange:NSMakeRange(0, 4) withBytes:&len];
    [block replaceBytesInRange:NSMakeRange(4, len) withBytes:hw.bytes];
    return block;
}

#pragma mark - Public

- (nullable NSNumber *)initializeWithHardwareID:(NSData *)hardwareID error:(NSError **)error
{
    _scratchCursor = 0;
    NSData *hw = [self hardwareBlock:hardwareID];
    uint64_t ctxField = [self scratchReserve:8];
    uint64_t hwAddr = [self scratchWrite:hw.bytes size:hw.length];
    uint64_t args[] = {ctxField, hwAddr};
    uint64_t status = [self invoke:[_resolvedEntries[@"_cp2g1b9ro"] unsignedLongLongValue] args:args count:2];
    _scratchCursor = 0;
    if ((int32_t)status != 0) {
        if (error) *error = [self machineError:[NSString stringWithFormat:@"SAP initialize returned %d", (int32_t)status]];
        return nil;
    }
    uint64_t ctx = [self readUint64:ctxField];
    if (ctx == 0) {
        if (error) *error = [self machineError:@"SAP initialize returned null context"];
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
    NSData *hw = [self hardwareBlock:hardwareID];
    uint64_t hwAddr = [self scratchWrite:hw.bytes size:hw.length];
    uint64_t inputAddr = [self scratchWrite:input.bytes size:input.length];
    uint64_t outField = [self scratchReserve:8];
    uint64_t lenField = [self scratchReserve:8];
    uint64_t resField = [self scratchReserve:4];
    uint64_t args[] = {version, hwAddr, context, inputAddr, (uint64_t)input.length, outField, lenField, resField};
    uint64_t status = [self invoke:[_resolvedEntries[@"_Mib5yocT"] unsignedLongLongValue] args:args count:8];
    if ((int32_t)status != 0) {
        _scratchCursor = 0;
        if (error) *error = [self machineError:[NSString stringWithFormat:@"SAP exchange returned %d", (int32_t)status]];
        return nil;
    }
    NSData *output = [self consumeOutput:outField lengthField:lenField];
    uint32_t result = [self readUint32:resField];
    _scratchCursor = 0;
    return @{@"output": output ?: [NSData data], @"state": @(result)};
}

- (nullable NSData *)signWithContext:(uint64_t)context input:(NSData *)input error:(NSError **)error
{
    _scratchCursor = 0;
    uint64_t inputAddr = [self scratchWrite:input.bytes size:input.length];
    uint64_t outField = [self scratchReserve:8];
    uint64_t lenField = [self scratchReserve:8];
    uint64_t args[] = {context, inputAddr, (uint64_t)input.length, outField, lenField};
    uint64_t status = [self invoke:[_resolvedEntries[@"_Fc3vhtJDvr"] unsignedLongLongValue] args:args count:5];
    if ((int32_t)status != 0) {
        _scratchCursor = 0;
        if (error) *error = [self machineError:[NSString stringWithFormat:@"SAP sign returned %d", (int32_t)status]];
        return nil;
    }
    NSData *output = [self consumeOutput:outField lengthField:lenField];
    _scratchCursor = 0;
    if (!output.length) {
        if (error) *error = [self machineError:@"SAP sign returned empty"];
        return nil;
    }
    return output;
}

- (BOOL)teardownWithContext:(uint64_t)context error:(NSError **)error
{
    _scratchCursor = 0;
    uint64_t args[] = {context};
    uint64_t status = [self invoke:[_resolvedEntries[@"_IPaI1oem5iL"] unsignedLongLongValue] args:args count:1];
    _scratchCursor = 0;
    if ((int32_t)status != 0) {
        if (error) *error = [self machineError:[NSString stringWithFormat:@"SAP teardown returned %d", (int32_t)status]];
        return NO;
    }
    return YES;
}

- (nullable NSString *)macAddress
{
    return @"02:00:00:00:00:00";
}

- (void)close
{
    if (_closed) return;
    _closed = YES;
    if (_unicorn) {
        if (_codeHook) { [_unicorn hookDel:_codeHook]; _codeHook = 0; }
        if (_memHook) { [_unicorn hookDel:_memHook]; _memHook = 0; }
        [_unicorn emuStop];
    }
    [_shims close];
    _shims = nil;
    if (_unicorn) {
        [_unicorn closeEngine]; _unicorn = nil;
    }
}

- (void)dealloc { [self close]; }

- (NSError *)machineError:(NSString *)msg
{
    return [NSError errorWithDomain:@"WFSSAPMachine" code:-1 userInfo:@{NSLocalizedDescriptionKey: msg}];
}

@end
