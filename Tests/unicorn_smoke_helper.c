#include <stdint.h>

static unsigned long wfs_smoke_hook_fires = 0;

void wfs_smoke_hook_cb(void *uc, uint64_t address, uint32_t size, uint64_t user_data)
{
    (void)uc;
    (void)address;
    (void)size;
    (void)user_data;
    wfs_smoke_hook_fires++;
}

uint64_t wfs_smoke_hook_count(void)
{
    return (uint64_t)wfs_smoke_hook_fires;
}

static unsigned long wfs_smoke_mem_fires = 0;

void wfs_smoke_mem_cb(void *uc, uint32_t type, uint64_t address, int size, int64_t value, uint64_t user_data)
{
    (void)uc;
    (void)type;
    (void)address;
    (void)size;
    (void)value;
    (void)user_data;
    wfs_smoke_mem_fires++;
}

uint64_t wfs_smoke_mem_count(void)
{
    return (uint64_t)wfs_smoke_mem_fires;
}