#ifndef WFSUnicorn_h
#define WFSUnicorn_h

#include <stdint.h>
#include <dlfcn.h>

#define UC_API_MAJOR 2
#define UC_API_MINOR 1

#define UC_ARCH_X86 4
#define UC_MODE_64  8

#define UC_PROT_READ   1
#define UC_PROT_WRITE  2
#define UC_PROT_EXEC   4
#define UC_PROT_ALL    7

#define UC_HOOK_INTR    (1 << 0)
#define UC_HOOK_INSN    (1 << 1)
#define UC_HOOK_CODE    (1 << 2)
#define UC_HOOK_BLOCK   (1 << 3)

#define UC_HOOK_MEM_READ_UNMAPPED   (1 << 4)
#define UC_HOOK_MEM_WRITE_UNMAPPED  (1 << 5)
#define UC_HOOK_MEM_FETCH_UNMAPPED  (1 << 6)
#define UC_HOOK_MEM_READ_PROT       (1 << 7)
#define UC_HOOK_MEM_WRITE_PROT      (1 << 8)
#define UC_HOOK_MEM_FETCH_PROT      (1 << 9)
#define UC_HOOK_MEM_READ            (1 << 10)
#define UC_HOOK_MEM_WRITE           (1 << 11)
#define UC_HOOK_MEM_FETCH           (1 << 12)

#define UC_MEM_READ                1
#define UC_MEM_WRITE               2
#define UC_MEM_FETCH               3
#define UC_MEM_READ_UNMAPPED       4
#define UC_MEM_WRITE_UNMAPPED      5
#define UC_MEM_FETCH_UNMAPPED      6
#define UC_MEM_READ_PROT           7
#define UC_MEM_WRITE_PROT          8
#define UC_MEM_FETCH_PROT          9
#define UC_MEM_READ_AFTER          10

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

typedef void *uc_engine;

typedef uint32_t (*uc_version_func)(uint32_t *major, uint32_t *minor);
typedef int (*uc_open_func)(uint32_t arch, uint32_t mode, uc_engine **uc);
typedef int (*uc_close_func)(uc_engine uc);
typedef int (*uc_mem_map_func)(uc_engine uc, uint64_t address, uint64_t size, uint32_t perms);
typedef int (*uc_mem_unmap_func)(uc_engine uc, uint64_t address, uint64_t size);
typedef int (*uc_mem_read_func)(uc_engine uc, uint64_t address, void *data, uint64_t size);
typedef int (*uc_mem_write_func)(uc_engine uc, uint64_t address, const void *data, uint64_t size);
typedef int (*uc_reg_read_func)(uc_engine uc, int regid, void *value);
typedef int (*uc_reg_write_func)(uc_engine uc, int regid, const void *value);
typedef int (*uc_emu_start_func)(uc_engine uc, uint64_t begin, uint64_t until, uint64_t timeout, uint64_t count);
typedef int (*uc_emu_stop_func)(uc_engine uc);
typedef int (*uc_hook_add_func)(uc_engine uc, void **hook, int type, void *callback, uint64_t begin, uint64_t end, uint64_t user_data);
typedef int (*uc_hook_del_func)(uc_engine uc, void *hook);
typedef const char* (*uc_strerror_func)(int code);
typedef int (*uc_ctl_func)(uc_engine uc, uint32_t control, ...);

typedef struct {
    void *handle;

    uc_version_func     version;
    uc_open_func        open;
    uc_close_func       close;
    uc_mem_map_func     memMap;
    uc_mem_unmap_func   memUnmap;
    uc_mem_read_func    memRead;
    uc_mem_write_func   memWrite;
    uc_reg_read_func    regRead;
    uc_reg_write_func   regWrite;
    uc_emu_start_func   emuStart;
    uc_emu_stop_func    emuStop;
    uc_hook_add_func    hookAdd;
    uc_hook_del_func    hookDel;
    uc_strerror_func    strerror;
} WFSUnicornAPI;

static inline int wfs_unicorn_load(WFSUnicornAPI *api) {
    void *handle = dlopen("libunicorn.2.dylib", RTLD_NOW);
    if (!handle) {
        handle = dlopen("libunicorn.dylib", RTLD_NOW);
    }
    if (!handle) {
        return -1;
    }

    api->handle   = handle;
    api->version  = (uc_version_func)dlsym(handle, "uc_version");
    api->open     = (uc_open_func)dlsym(handle, "uc_open");
    api->close    = (uc_close_func)dlsym(handle, "uc_close");
    api->memMap   = (uc_mem_map_func)dlsym(handle, "uc_mem_map");
    api->memUnmap = (uc_mem_unmap_func)dlsym(handle, "uc_mem_unmap");
    api->memRead  = (uc_mem_read_func)dlsym(handle, "uc_mem_read");
    api->memWrite = (uc_mem_write_func)dlsym(handle, "uc_mem_write");
    api->regRead  = (uc_reg_read_func)dlsym(handle, "uc_reg_read");
    api->regWrite = (uc_reg_write_func)dlsym(handle, "uc_reg_write");
    api->emuStart = (uc_emu_start_func)dlsym(handle, "uc_emu_start");
    api->emuStop  = (uc_emu_stop_func)dlsym(handle, "uc_emu_stop");
    api->hookAdd  = (uc_hook_add_func)dlsym(handle, "uc_hook_add");
    api->hookDel  = (uc_hook_del_func)dlsym(handle, "uc_hook_del");
    api->strerror = (uc_strerror_func)dlsym(handle, "uc_strerror");

    if (!api->version || !api->open || !api->close || !api->memMap ||
        !api->memRead || !api->memWrite || !api->regRead || !api->regWrite ||
        !api->emuStart) {
        dlclose(handle);
        return -1;
    }

    return 0;
}

static inline void wfs_unicorn_unload(WFSUnicornAPI *api) {
    if (api->handle) {
        dlclose(api->handle);
        api->handle = NULL;
    }
}

#endif
