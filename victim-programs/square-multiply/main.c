#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

//#define DEBUGMODE

#define KEY_FILE "key.hex"

__attribute__((aligned(4096), noinline))
uint64_t square(uint64_t x) {
    asm volatile("nop" ::: "memory");  // prevent inlining function
    return x * x;
}

__attribute__((aligned(4096), noinline))
uint64_t multiply(uint64_t x, uint64_t y) {
    asm volatile("nop" ::: "memory");  // prevent inlining function
    return x * y;
}

__attribute__((aligned(4096), noinline))
uint64_t mod_exp_inner(uint64_t base,
        const char* exp,
        size_t exp_bits,
        uint64_t mod) {
    uint64_t result = 1;
    for (int i = 0; i < exp_bits; i++) {
        result = square(result);
        if (exp[i] == '1') {
            result = multiply(result, base);
        }
        result = result % mod;
    }
    return result;
}

char __attribute__((aligned(4096))) key[] = "1010100100011010010101110000110010011111011100001100000010001000101000001100101111010011101011100001110110101110100100010101110101110001101111000001010100011010001100110001111101000101011101010100100101010010111010011000100110000111011011000001001111001000";

uint64_t __attribute__((aligned(4096))) mod_exp() {
    uint64_t base = 3;  // plaintext
    uint64_t modulus = 0x80000000;
    return mod_exp_inner(base, key, KEYSIZE, modulus);
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
        key[i] = lcg() % 2 ? '1' : '0';
    }

    key[KEYSIZE - 1] = '1';
}

void log_key() {
    FILE* fd = fopen(KEY_FILE, "w");
    for (int i = 0; i < KEYSIZE; i++) {
        fprintf(fd, "%c", key[i]);
    }
    fclose(fd);
}

int main(int argc, char* argv[]) {
    generate_key();
#ifdef DEBUGMODE
    printf("Seed: %d\n", SEED);
    printf("Key Size: %d\n", KEYSIZE);
    printf("Key: %s\n", key);
#endif
    // victim call
    uint64_t result = mod_exp();

    // log the key for postprocessing purposes
    log_key();
#ifdef DEBUGMODE
    printf("Result: %lx\n", result);
#endif
    return 0;
}
