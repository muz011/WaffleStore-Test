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