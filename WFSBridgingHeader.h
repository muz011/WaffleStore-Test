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
    UC_HOOK_INTR                = 1 << 0,
    UC_HOOK_INSN                = 1 << 1,
    UC_HOOK_CODE                = 1 << 2,
    UC_HOOK_BLOCK               = 1 << 3,
};

enum {
    UC_HOOK_MEM_READ_UNMAPPED   = 1 << 4,
    UC_HOOK_MEM_WRITE_UNMAPPED  = 1 << 5,
    UC_HOOK_MEM_FETCH_UNMAPPED  = 1 << 6,
    UC_HOOK_MEM_READ_PROT       = 1 << 7,
    UC_HOOK_MEM_WRITE_PROT      = 1 << 8,
    UC_HOOK_MEM_FETCH_PROT      = 1 << 9,
    UC_HOOK_MEM_READ            = 1 << 10,
    UC_HOOK_MEM_WRITE           = 1 << 11,
    UC_HOOK_MEM_FETCH           = 1 << 12,
};

typedef enum {
    UC_MEM_READ                = 1,
    UC_MEM_WRITE               = 2,
    UC_MEM_FETCH               = 3,
    UC_MEM_READ_UNMAPPED       = 4,
    UC_MEM_WRITE_UNMAPPED      = 5,
    UC_MEM_FETCH_UNMAPPED      = 6,
    UC_MEM_READ_PROT           = 7,
    UC_MEM_WRITE_PROT          = 8,
    UC_MEM_FETCH_PROT          = 9,
    UC_MEM_READ_AFTER          = 10,
} wfs_uc_mem_type;

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
