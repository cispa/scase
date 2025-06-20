#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

//#define DEBUGMODE

#define PADDING 4096
#define KEY_FILE "key.hex"

/* Helpers */
unsigned char dec_to_hex[] = "0123456789abcdef";


unsigned char hex_to_dec_lut[256];

void init_hex_to_dec() {
    // we taint illegal values to ensure that 
    // we can't have illegal values leading to "correct" results
    for (int i = 0; i < 256; i++) {
        hex_to_dec_lut[i] = 0xff;
    }
    for (int c = '0'; c <= '9'; c++) {
        hex_to_dec_lut[c] = c - '0';
    }
    // TODO: be careful, we only supp lower case chars
    for (int c = 'a'; c <= 'z'; c++) {
        hex_to_dec_lut[c] = c - 'a' + 10;
    }
}

unsigned char hex_to_dec(unsigned char c) {
    // we assume valid input
    return hex_to_dec_lut[c];
}

unsigned char __attribute__((aligned(4096))) key[] = "1597f75969b8b22f36069b245e154f5190d260fca8986c491b1ecd52eadef4ae";  // default length = 64

/* Jump Functions */
unsigned char buffer[KEYSIZE] = {0};
unsigned int buffer_pos = 0;

void func_0() { buffer[buffer_pos++] = '0'; }
void func_1() { buffer[buffer_pos++] = '1'; }
void func_2() { buffer[buffer_pos++] = '2'; }
void func_3() { buffer[buffer_pos++] = '3'; }
void func_4() { buffer[buffer_pos++] = '4'; }
void func_5() { buffer[buffer_pos++] = '5'; }
void func_6() { buffer[buffer_pos++] = '6'; }
void func_7() { buffer[buffer_pos++] = '7'; }
void func_8() { buffer[buffer_pos++] = '8'; }
void func_9() { buffer[buffer_pos++] = '9'; }
void func_a() { buffer[buffer_pos++] = 'a'; }
void func_b() { buffer[buffer_pos++] = 'b'; }
void func_c() { buffer[buffer_pos++] = 'c'; }
void func_d() { buffer[buffer_pos++] = 'd'; }
void func_e() { buffer[buffer_pos++] = 'e'; }
void func_f() { buffer[buffer_pos++] = 'f'; }

/* Lookup Table */
struct lut_entry {
    void* func;
    char padding[PADDING];
};

struct lut_entry __attribute__((aligned(4096))) lut[16] = {
    {&func_0, {0}},
    {&func_1, {0}},
    {&func_2, {0}},
    {&func_3, {0}},
    {&func_4, {0}},
    {&func_5, {0}},
    {&func_6, {0}},
    {&func_7, {0}},
    {&func_8, {0}},
    {&func_9, {0}},
    {&func_a, {0}},
    {&func_b, {0}},
    {&func_c, {0}},
    {&func_d, {0}},
    {&func_e, {0}},
    {&func_f, {0}},
};

/* Victim Functions */
void __attribute__((aligned(4096))) something(unsigned char* key, int len, struct lut_entry* lut) {
    for (int i = 0; i < len; i++) {
        int idx = hex_to_dec(key[i]);
        ((void (*)())lut[idx].func)();
    }
}

void __attribute__((aligned(4096))) do_something() {
    init_hex_to_dec();
    something(key, KEYSIZE, lut);
}

static unsigned long next = 0;
int lcg(void) {
    next = next * 1103515245 + 12345;
    return((unsigned)(next/65536) % 32768);
}

void generate_key() {
    // set set for LCG
    next = SEED;

    for (int i = 0; i < KEYSIZE; i++) {
        key[i] = dec_to_hex[lcg() % 16];
    }
}

void log_key() {
    FILE* fd = fopen(KEY_FILE, "w");
    for (int i = 0; i < KEYSIZE; i++) {
        fprintf(fd, "%c", key[i]);
    }
    fclose(fd);
}


int main() {
    generate_key();
#ifdef DEBUGMODE
    printf("Seed: %d\n", SEED);
    printf("Key: %s\n", key);
#endif
    // victim call
    do_something();

    // log the key for postprocessing purposes
    log_key();
#ifdef DEBUGMODE
    printf("Buffer: %s\n", key);
#endif
    return 0;
}
