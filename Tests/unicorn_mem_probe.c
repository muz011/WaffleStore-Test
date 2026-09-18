#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>

typedef void *uc_engine;

typedef int (*open_fn)(uint32_t, uint32_t, uc_engine **);
typedef int (*map_fn)(uc_engine, uint64_t, uint64_t, uint32_t);
typedef int (*write_fn)(uc_engine, uint64_t, const void *, uint64_t);
typedef int (*start_fn)(uc_engine, uint64_t, uint64_t, uint64_t, uint64_t);
typedef int (*hookadd_fn)(uc_engine, void **, int, void *, uint64_t, uint64_t, uint64_t);
typedef int (*close_fn)(uc_engine);
typedef const char *(*strerr_fn)(int);

#define UC_HOOK_MEM_WRITE          (1 << 11)
#define UC_HOOK_MEM_WRITE_UNMAPPED (1 << 5)

static unsigned long write_fires = 0;
static unsigned long unmapped_fires = 0;

static void on_write(void *uc, uint32_t type, uint64_t addr, int size, int64_t value, void *ud)
{
    (void)uc; (void)ud;
    printf("  on_write type=%u addr=0x%llx size=%d value=%lld\n", type, (unsigned long long)addr, size, (long long)value);
    write_fires++;
}

static void on_unmapped(void *uc, uint32_t type, uint64_t addr, int size, int64_t value, void *ud)
{
    (void)uc; (void)ud;
    printf("  on_unmapped type=%u addr=0x%llx size=%d value=%lld\n", type, (unsigned long long)addr, size, (long long)value);
    unmapped_fires++;
}

int main(int argc, char **argv)
{
    const char *libpath = argc > 1 ? argv[1] : "libunicorn.2.dylib";
    void *h = dlopen(libpath, RTLD_NOW);
    if (!h) {
        printf("dlopen failed: %s\n", dlerror());
        return 2;
    }

    open_fn open_ = (open_fn)dlsym(h, "uc_open");
    map_fn map_ = (map_fn)dlsym(h, "uc_mem_map");
    write_fn write_ = (write_fn)dlsym(h, "uc_mem_write");
    start_fn start_ = (start_fn)dlsym(h, "uc_emu_start");
    hookadd_fn hookadd_ = (hookadd_fn)dlsym(h, "uc_hook_add");
    close_fn close_ = (close_fn)dlsym(h, "uc_close");
    strerr_fn strerr_ = (strerr_fn)dlsym(h, "uc_strerror");

    if (!open_ || !map_ || !write_ || !start_ || !hookadd_ || !close_ || !strerr_) {
        printf("missing unicorn symbols\n");
        return 2;
    }

    uc_engine uc = NULL;
    int rc = open_(4, 8, &uc);
    printf("open rc=%d\n", rc);

    rc = map_(uc, 0x10000, 0x1000, 7);
    printf("map 0x10000 rc=%d\n", rc);
    rc = map_(uc, 0x20000, 0x1000, 7);
    printf("map 0x20000 rc=%d\n", rc);

    uint8_t mapped_write[] = {
        0xC7, 0x04, 0x25, 0x00, 0x00, 0x11, 0x00, 0x2A, 0x00, 0x00, 0x00,  /* mov dword [0x11000], 42 */
        0x90,                                                               /* nop */
        0x48, 0xB8, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* mov rax, 0x99 */
    };
    uint8_t unmapped_write[] = {
        0xC7, 0x04, 0x25, 0x00, 0x00, 0x60, 0x00, 0x2A, 0x00, 0x00, 0x00,  /* mov dword [0x60000], 42 */
        0x90,                                                               /* nop */
        0x48, 0xB8, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* mov rax, 0x99 */
    };
    write_(uc, 0x10000, mapped_write, sizeof(mapped_write));
    write_(uc, 0x20000, unmapped_write, sizeof(unmapped_write));
    printf("code written\n");

    rc = hookadd_(uc, NULL, UC_HOOK_MEM_WRITE, (void *)on_write, 0, 0, 0);
    printf("hookadd WRITE rc=%d\n", rc);
    rc = hookadd_(uc, NULL, UC_HOOK_MEM_WRITE_UNMAPPED, (void *)on_unmapped, 0, 0, 0);
    printf("hookadd WRITE_UNMAPPED rc=%d\n", rc);

    write_fires = unmapped_fires = 0;
    rc = start_(uc, 0x10000, 0x10000 + sizeof(mapped_write), 0, 0);
    printf("run mapped-write rc=%d (%s) write_fires=%lu unmapped_fires=%lu\n",
           rc, strerr_(rc), write_fires, unmapped_fires);

    write_fires = unmapped_fires = 0;
    rc = start_(uc, 0x20000, 0x20000 + sizeof(unmapped_write), 0, 0);
    printf("run unmapped-write rc=%d (%s) write_fires=%lu unmapped_fires=%lu\n",
           rc, strerr_(rc), write_fires, unmapped_fires);

    close_(uc);
    dlclose(h);
    return 0;
}