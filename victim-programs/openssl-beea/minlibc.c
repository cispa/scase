#include <stdlib.h>  // for size_t

#include "minlibc.h"

#define HEAP_SIZE (10 * 1024 * 1024)

static char heap[HEAP_SIZE];
char* current_heap_position = heap;

void* malloc(size_t size) {

  // check if the heap has enough space left
  if (current_heap_position + size > heap + HEAP_SIZE) {
    exit(-1);
    return NULL;
  }

  // we just return pointers to our heap array
  char* ptr = current_heap_position;
  current_heap_position += size;
  return ptr;
}

void* calloc(size_t nmemb, size_t size) {
  void* ptr = malloc(nmemb * size);
  memset(ptr, 0, nmemb * size);
  return ptr;
}

void free(void* ptr) {}

void* realloc(void* ptr, size_t size) {
  void* ptr_new = malloc(size);
  if (ptr_new == NULL) {
    return NULL;
  }
  if (ptr == NULL) {
    // realloc(NULL, size) behaves like malloc(size)
    return ptr_new;
  }
  memcpy(ptr_new, ptr, size);
  return ptr_new;
}

__attribute__((noinline))
void* memset(void* s, int c, size_t n) {
    unsigned char* dst = (unsigned char*)s;
    while (n--) {
        *dst++ = c;
        // confuse compiler to not optimize to a call to memset()
        asm volatile(
            "addq $1, %%rax\n\t"
            "subq $1, %%rax\n\t"
        ::: "memory");
    }
    return s;
}

__attribute__((noinline))
void* memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) {
        *d++ = *s++;
        // confuse compiler to not optimize
        asm volatile(
            "addq $1, %%rax\n\t"
            "subq $1, %%rax\n\t"
        ::: "memory");
    }
    return dest;
}

char* strchr(const char *s, int c) {
    while (*s != '\0') {
        if (*s == c) {
            return (char*)s;
        }
        s++;
    }
    return NULL;
}

char* strchrnul(const char *s, int c) {
    while (*s != '\0') {
        if (*s == c) {
            return (char*)s;
        }
        s++;
    }
    return (char*)s;
}
