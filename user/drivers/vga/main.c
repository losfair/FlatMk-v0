#include <stdio.h>
#include <stddriver.h>
#include <x86intrin.h>
#include <stdatomic.h>
#include "vgamode.h"

#define FB_WIDTH 640
#define FB_HEIGHT 480

CPtr log_task_cap = 0x10;
CPtr render_task_cap = 0x11;
struct TaskEndpoint CAP_FRAMEBUFFER = { 0x12 };
struct TaskEndpoint CAP_BUFFER_INITRET = { 0x13 };
const uint64_t rerender_interval_ms = 16; // 60 FPS

_Atomic uint64_t frame_count = 0;
_Atomic uint64_t tsc_freq = 0;
uint8_t __log_stack[4096];
uint8_t __render_stack[65536];

volatile uint8_t *vga_memory_start = (uint8_t *) 0xa0000;
volatile uint8_t *vga_memory_end = (uint8_t *) 0xc0000;

struct __attribute__((packed)) Pixel {
    uint8_t r, g, b;
};

struct Pixel *shared_fb = (struct Pixel *) 0x30000000;
uint8_t local_fb[FB_WIDTH * FB_HEIGHT];
uint8_t fb_changed[FB_WIDTH * FB_HEIGHT];

static uint8_t PAL16[48] = {
    0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x80,0x00,0x00,0x80,0x80,0x80,0x00,0x00,
    0x80,0x00,0x80,0x80,0x80,0x00,0xc0,0xc0,0xc0,0x80,0x80,0x80,0x00,0x00,0xff,
    0x00,0xff,0x00,0x00,0xff,0xff,0xff,0x00,0x00,0xff,0x00,0xff,0xff,0xff,0x00,
    0xff,0xff,0xff
};

uint8_t pixel_to_palette(const struct Pixel* pix) {
    int best = -1;
    int min_dist = -1;

    for(int i = 0; i < 16; i++) {
        int r = PAL16[i * 3];
        int g = PAL16[i * 3 + 1];
        int b = PAL16[i * 3 + 2];

        int dist = (r - (int) pix->r) * (r - (int) pix->r) + (g - (int) pix->g) * (g - (int) pix->g) + (b - (int) pix->b) * (b - (int) pix->b);
        if(min_dist == -1 || dist < min_dist) {
            min_dist = dist;
            best = i;
        }
    }

    return best;
}

uint64_t calibrate_tsc_once_tenms() {
    uint64_t interval1, interval2;

    do {
        uint64_t start1 = __builtin_ia32_rdtsc();
        sched_nanosleep(0);
        uint64_t end1 = __builtin_ia32_rdtsc();

        uint64_t start2 = __builtin_ia32_rdtsc();
        sched_nanosleep(10000000); // 10 milliseconds
        uint64_t end2 = __builtin_ia32_rdtsc();

        interval1 = end1 - start1;
        interval2 = end2 - start2;
    } while(interval1 > interval2);

    return interval2 - interval1;
}

uint64_t calibrate_tsc() {
    uint64_t result = 0;
    int i;
    for(i = 0; i < 100; i++) result += calibrate_tsc_once_tenms();
    return result;
}

void log_entry() {
    char buf[128];
    
    while(1) {
        uint64_t count = atomic_exchange(&frame_count, 0);
        sprintf(buf, "vga: FPS = %llu\n", count);
        flatmk_debug_puts(buf);
        sched_nanosleep(1000000000ull);
    }
}

void map_shared_fb(struct BasicTask this_task) {
    struct FastIpcPayload payload = {0};

    // Create
    payload.data[0] = 0;

    // Size
    payload.data[1] = FB_WIDTH * FB_HEIGHT * sizeof(struct Pixel);

    while(1) {
        fastipc_write(&payload);

        // Wait until shmem_create becomes available.
        if(TaskEndpoint_invoke(CAP_SHMEM_CREATE) < 0) {
            // sched_yield invalidates fastipc registers.
            sched_yield();
            continue;
        }

        fastipc_read(&payload);

        if((int64_t) payload.data[0] < 0) {
            flatmk_debug_puts("Cannot create framebuffer.\n");
            flatmk_throw();
        }

        if(BasicTask_fetch_ipc_cap(this_task, CAP_FRAMEBUFFER.cap, 1) < 0) {
            flatmk_throw();
        }

        break;
    }

    // Create local mapping.
    payload.data[0] = 0;
    payload.data[1] = (uint64_t) shared_fb;
    payload.data[2] = FB_WIDTH * FB_HEIGHT * sizeof(struct Pixel);

    // Put local page table.
    if(CapabilitySet_clone_cap(CAP_CAPSET, CAP_RPT.cap, CAP_BUFFER) < 0) flatmk_throw();
    if(BasicTask_put_ipc_cap(this_task, CAP_BUFFER, 1) < 0) flatmk_throw();
    
    while(1) {
        fastipc_write(&payload);

        // Wait until endpoint becomes available.
        if(TaskEndpoint_invoke(CAP_FRAMEBUFFER) < 0) {
            // sched_yield invalidates fastipc registers.
            sched_yield();
            continue;
        }

        fastipc_read(&payload);

        if((int64_t) payload.data[0] < 0) {
            flatmk_debug_puts("Cannot map framebuffer.\n");
            flatmk_throw();
        }

        // Check that mapping actually succeeded.
        if(shared_fb[0].r != 0) flatmk_throw();

        break;
    }
}


uint64_t tsc_to_ms(uint64_t tsc) {
    return tsc * 1000 / tsc_freq;
}

void rerender() {
    int plane, x, y;

    for(int i = 0; i < FB_WIDTH * FB_HEIGHT; i++) {
        uint8_t color = pixel_to_palette(&shared_fb[i]);
        if(color != local_fb[i]) {
            local_fb[i] = color;
            fb_changed[i] = 1;
        } else {
            fb_changed[i] = 0;
        }
    }

    for(plane = 0; plane < 4; plane++) {
        VGAWriteReg(VGA_SEQ, VGA__SEQ__MAP, 1<<plane);
        VGAWriteReg(VGA_GCT, VGA__GCT__RDM, plane);
        for(y = 0; y < FB_HEIGHT; y++) {
            int any_changed = 0;
            uint8_t pixelbuf = 0;

            for(x = 0; x < FB_WIDTH; x++) {
                int index = y * FB_WIDTH + x;
                if(fb_changed[index]) {
                    uint8_t mask = 1 << (7 - (x & 7));
                    uint8_t color = local_fb[index];
                    if(color & (1 << plane)) {
                        pixelbuf |= mask;
                    }
                    any_changed = 1;
                }

                if((x + 1) % 8 == 0) {
                    if(any_changed) {
                        volatile uint8_t *pixel = vga_memory_start + (index >> 3);
                        *pixel = pixelbuf;
                        pixelbuf = 0;
                        any_changed = 0;
                    }
                }
            }
        }
    }
}

void render_loop() {
    static uint64_t last_rerender_tsc = 0;

    char buf[256];

    while(1) {
        uint64_t current = __builtin_ia32_rdtsc();
        uint64_t diff_ms = tsc_to_ms(current - last_rerender_tsc);
        
        if(diff_ms >= rerender_interval_ms) {
            // Immediately re-render.
        } else if(diff_ms + 1 >= rerender_interval_ms) {
            // Busy wait if within 1 millisecond.
            continue;
        } else {
            // diff_ms + 1 < rerender_interval_ms.
            // we can sleep for some time.
            sched_nanosleep((rerender_interval_ms - diff_ms - 1) * 1000000);
            continue;
        }

        last_rerender_tsc = current;

        uint64_t render_start = __builtin_ia32_rdtsc();
        rerender();
        uint64_t render_end = __builtin_ia32_rdtsc();
        uint64_t render_ms = tsc_to_ms(render_end - render_start);
        if(render_ms > rerender_interval_ms) {
            sprintf(buf, "vga: Rendering took too long (%llu milliseconds).\n", render_ms);
            flatmk_debug_puts(buf);
        }
        atomic_fetch_add(&frame_count, 1);
    }
}

void main() {
    // Save the return endpoint before IPC calls.
    if(
        BasicTask_fetch_ipc_cap(CAP_ME, CAP_BUFFER_INITRET.cap, 0) < 0
    ) flatmk_throw();

    char buf[256];
    tsc_freq = calibrate_tsc();

    map_shared_fb(CAP_ME);
    flatmk_debug_puts("vga: Shared framebuffer initialized.\n");

    // Set VGA mode to 640x480x4bit.
    VGAMode(2, 640, 480, 0);
    VGASetPal(PAL16, 0, 16);

    sprintf(buf, "vga: Flushing framebuffer.\n");
    flatmk_debug_puts(buf);

    uint64_t flush_start = __builtin_ia32_rdtsc();
    for(int i = 0; i < FB_HEIGHT * FB_WIDTH; i++) {
        shared_fb[i].r = 0xff;
        shared_fb[i].g = 0xff;
        shared_fb[i].b = 0xff;
    }
    uint64_t flush_end = __builtin_ia32_rdtsc();

    sprintf(buf, "vga: Flushed local framebuffer. Took %llu milliseconds.\n", tsc_to_ms(flush_end - flush_start));
    flatmk_debug_puts(buf);

    // Start worker threads.
    start_thread(BasicTask_new(log_task_cap), (uint64_t) log_entry, (uint64_t) __log_stack + sizeof(__log_stack) - 8, FLATRT_DRIVER_GLOBAL_TLS, NULL);
    start_thread(BasicTask_new(render_task_cap), (uint64_t) render_loop, (uint64_t) __render_stack + sizeof(__render_stack) - 8, FLATRT_DRIVER_GLOBAL_TLS, NULL);

    sprintf(buf, "vga: Started. Initial TSC frequency: %llu\n", tsc_freq);
    flatmk_debug_puts(buf);

    // Return.
    TaskEndpoint_invoke(CAP_BUFFER_INITRET);
    flatmk_throw();
}
