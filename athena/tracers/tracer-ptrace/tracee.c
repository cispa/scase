#define _GNU_SOURCE
#include <memory.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <x86intrin.h>
#include <immintrin.h>
#include <sys/mman.h>

static inline void maccess(void *p) {
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
  asm volatile("mfence\n" ::: "memory");
}

void list_executable_pages(pid_t pid) {
  char fname[256] = {0};
  snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);
  printf("fname: %s\n", fname);
  FILE *maps_file = fopen(fname, "r");
  if (maps_file == NULL) {
    exit(1);
  }

  char line[256];
  while (fgets(line, sizeof(line), maps_file)) {
    // Example line format:
    // 00400000-00452000 r-xp 00000000 08:01 123456  /usr/bin/cat

    unsigned long start, end;
    char perms[5];  // To store permission string like "r-xp"
    char pathname[256] = {0};
    
    // Parse the start and end addresses and permissions
    int parsed_fields = sscanf(
        line, 
        "%lx-%lx %4s %*s %*s %*s %255s", 
        &start, &end, perms, pathname);
    if (parsed_fields > 3) {
      // Check if the page has executable permissions (check 'x' in perms)
      if (strchr(perms, 'x') != NULL) {
        printf("Executable pages: %lx-%lx -> %s\n", start, end, pathname);
      }
    }
  }
  fclose(maps_file);
}


#define ADDR1 (void*)0x13370000
#define ADDR2 (void*)0x13380000
#define ADDR3 (void*)0x13390000

__attribute__((aligned(4096))) char page1[4096];
__attribute__((aligned(4096))) char page2[4096];
__attribute__((aligned(4096))) char page3[4096];


__attribute__((aligned(4096)))
void touch_page1() {
  maccess(page1);
}

__attribute__((aligned(4096)))
void touch_page2() {
  maccess(page2);
}

__attribute__((aligned(4096)))
void touch_page3() {
  maccess(page3);
}


int main() {

    //char* page1 = mmap(ADDR1,
    //                  4096,
    //                  PROT_READ | PROT_WRITE,
    //                  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
    //                  -1,
    //                  0);
    //char* page2 = mmap(ADDR2,
    //                  4096,
    //                  PROT_READ | PROT_WRITE,
    //                  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
    //                  -1,
    //                  0);
    //char* page3 = mmap(ADDR3,
    //                  4096,
    //                  PROT_READ | PROT_WRITE,
    //                  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
    //                  -1,
    //                  0);
    //assert(page1 == ADDR1);
    //assert(page2 == ADDR2);
    //assert(page3 == ADDR3);
    //printf("[tracee] main @ %p\n", main);
    //printf("[tracee] page1: %p\n", &page1);
    //printf("[tracee] page2: %p\n", &page2);
    //printf("[tracee] page3: %p\n", &page3);

    for (int i = 0; i < 10; i++) {
      touch_page1();
      touch_page2();
      touch_page3();
    }

    touch_page3();
    touch_page2();
    touch_page1();

    return 0;
}
