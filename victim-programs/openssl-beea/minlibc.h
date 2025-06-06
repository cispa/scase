#ifndef MINLIBC_H
#define MINLIBC_H

// === minlibc ===
// This library acts as a replacement for certain functions of the 
// standard C library. The functions are implemented to reduce the complexity
// when executing or emulating these functions. 
//
// Disclaimer: This library is not intended to be used in production code.
//   Functions prefer minimal footprint over error checking and may stop working
//   for corner cases, e.g., malloc() is restricted to a fixed amount of memory.
// ===============

void* malloc(size_t size);
void* calloc(size_t nmemb, size_t size);
void  free(void* ptr);
void* realloc(void*ptr, size_t size);

void* memset(void* s, int c, size_t n);
void* memcpy(void* dest, const void* src, size_t n);

char* strchr(const char *s, int c);

char* strchrnul(const char *s, int c);

#endif /* !MINLIBC_H */
