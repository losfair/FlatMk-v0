#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

struct __attribute__((packed)) Pixel {
    uint8_t r, g, b;
};

struct Pixel *framebuffer = (struct Pixel *) 0x300000000000;

int main() {
    printf("Hello, world!\n");
    fflush(stdout);

    uint64_t start = __builtin_ia32_rdtsc();
    for(int i = 0; i < 1000000; i++) {
        getuid();
    }
    uint64_t end = __builtin_ia32_rdtsc();
    printf("Linux ABI benchmark: %lu cycles per syscall\n", (end - start) / 1000000);
    fflush(stdout);

    int vga_fd = open("/dev/vga", O_RDWR);
    if(vga_fd < 0) {
        printf("Cannot open vga\n");
        return 1;
    }

    int kbd_fd = open("/dev/kbd", O_RDWR);
    if(kbd_fd < 0) {
        printf("Cannot open keyboard\n");
        return 1;
    }
    while(1) {
        uint8_t scancode = 0;
        if(read(kbd_fd, &scancode, 1) != 1) {
            printf("Cannot read from keyboard\n");
            return 1;
        }
        printf("Scancode: %d\n", (int) scancode);
        fflush(stdout);
    }

    return 0;
}
