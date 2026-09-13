#ifndef WFSBridgingHeader_h
#define WFSBridgingHeader_h

#include <stdint.h>

typedef void *uc_engine_t;

enum {
    UC_ARCH_X86 = 4,
    UC_MODE_64  = 8,
};

enum {
    UC_PROT_READ   = 1,
    UC_PROT_WRITE  = 2,
    UC_PROT_EXEC   = 4,
    UC_PROT_ALL    = 7,
};

enum {
    UC_HOOK_CODE        = 1,
    UC_HOOK_BLOCK       = 2,
    UC_HOOK_MEM_UNMAPPED = 0x10,
};

enum {
    UC_MEM_READ_UNMAPPED  = 1,
    UC_MEM_WRITE_UNMAPPED = 2,
    UC_MEM_FETCH_UNMAPPED = 3,
};

enum uc_x86_reg {
    UC_X86_REG_RAX = 35,
    UC_X86_REG_RCX = 38,
    UC_X86_REG_RDI = 39,
    UC_X86_REG_RDX = 40,
    UC_X86_REG_RIP = 41,
    UC_X86_REG_RSI = 43,
    UC_X86_REG_RSP = 44,
    UC_X86_REG_R8  = 106,
    UC_X86_REG_R9  = 107,
};

#endif
