#include <stddriver.h>

#define FB_WIDTH 1024
#define FB_HEIGHT 768

struct __attribute__((packed)) Pixel {
    uint8_t r, g, b;
};

// Provided by init.
struct TaskEndpoint CAP_FRAMEBUFFER = { 0x10 };

struct TaskEndpoint CAP_BUFFER_INITRET = { 0x11 };
struct BasicTask CAP_THREAD_TIMER = { 0x12 };

struct Pixel *framebuffer = (struct Pixel *) 0x50000000;

uint8_t __thread_timer_stack[65536];

int render_rect(int x1, int y1, int x2, int y2) {
    for(int i = x1; i <= x2; i++) {
        for(int j = y1; j <= y2; j++) {
            if(i >= FB_WIDTH || j >= FB_HEIGHT) continue;
            framebuffer[j * FB_WIDTH + i].r = 255;
            framebuffer[j * FB_WIDTH + i].b = 255;
        }
    }
}

void render_counter(uint8_t v) {
    for(int i = 0; i < FB_HEIGHT * FB_WIDTH; i++) {
        framebuffer[i].r = 0;
        framebuffer[i].g = 0;
        framebuffer[i].b = 0;
    }
    for(int i = 0; i < 7; i++) {
        if((v >> i) & 1) {
            int x1 = 50 + (7 - i) * 50;
            int y1 = 50;
            render_rect(x1, y1, x1 + 25, y1 + 25);
        }
    }
}

void thread_timer() {
    static uint8_t counter = 0;

    while(1) {
        counter++;
        render_counter(counter);
        sched_nanosleep(1000000000);
    }
}

void main() {
    // Save the return endpoint before IPC calls.
    if(
        BasicTask_fetch_ipc_cap(CAP_ME, CAP_BUFFER_INITRET.cap, 0) < 0
    ) flatmk_throw();

    // Map framebuffer.
    if(flatrt_shmem_map(CAP_ME, CAP_FRAMEBUFFER, framebuffer, FB_WIDTH * FB_HEIGHT * sizeof(struct Pixel)) < 0) {
        flatmk_debug_puts("gclock: Cannot map shared framebuffer.\n");
        flatmk_throw();
    }

    for(int i = 0; i < FB_HEIGHT * FB_WIDTH; i++) {
        framebuffer[i].r = 0;
        framebuffer[i].g = 0;
        framebuffer[i].b = 0;
    }

    flatrt_start_thread(CAP_ME, CAP_THREAD_TIMER, (uint64_t) thread_timer, (uint64_t) __thread_timer_stack + sizeof(__thread_timer_stack) - 8, FLATRT_DRIVER_GLOBAL_TLS, NULL);

    // Return.
    TaskEndpoint_invoke(CAP_BUFFER_INITRET);
    flatmk_throw();
}