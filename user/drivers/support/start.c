#include <stddriver.h>

void main();

unsigned char FLATRT_DRIVER_GLOBAL_TLS[4096 * 16];

// FIXME: Copy TLS image?
static __attribute__((noinline)) void flatmk_init() {
    // This causes "Page fault at 0xd8".
    //__copy_tls(TLS);

    flatmk_set_fs_base((uint64_t) FLATRT_DRIVER_GLOBAL_TLS);

    BasicTask_fetch_capset(CAP_ME, CAP_CAPSET.cap);
    BasicTask_fetch_root_page_table(CAP_ME, CAP_RPT.cap);

    libmalloc_init(DYNAMIC_ALLOC_BASE, CAP_RPT.cap);
    libcapalloc_init(CAP_CAPSET.cap, CAP_DYNAMIC_BASE);
}

void __attribute__((noinline)) __flatrt_driver_start() {
    flatmk_init();
    main();
}

// The entry point.
// Sets up stack alignment, and calls `__flatrt_driver_start`.
void __attribute__((naked)) _start() {
    __asm__ volatile (
        "call __flatrt_driver_start\n"
        "ud2\n"
    );
}
