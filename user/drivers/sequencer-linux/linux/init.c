#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int main() {
    char *str = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    str[10] = 42;
    __asm__ volatile("nop" :: "r"(str) :);
    printf("Hello, world!\n");

    for(int i = 0; i < 1000000; i++) {
        getuid();
    }

    uint64_t start = __builtin_ia32_rdtsc();
    for(int i = 0; i < 1000000; i++) {
        getuid();
    }
    uint64_t end = __builtin_ia32_rdtsc();
    printf("%lu cycles per syscall\n", (end - start) / 1000000);
    fflush(stdout);
    while(1) sleep(10);

    return 0;
}
