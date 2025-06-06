#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#define N 256
#define STRETCH_FACTOR 1

//#define KEY_SIZE 64
#define KEY_SIZE 32

#define KEY_FILE "key.hex"

unsigned char S[N*STRETCH_FACTOR] = {0};
unsigned char key[KEY_SIZE] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};  // default length = 8

void __attribute__((aligned(4096))) swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void __attribute__((aligned(4096))) KSA(unsigned char* key, int len, unsigned char* S) {
    int j = 0;

    for (int i = 0; i < N; i++)
        S[i*STRETCH_FACTOR] = i;

    for (int i = 0; i < N; i++)
    {
        j = (j + S[i] + key[i % len]) % N;
        swap(&S[i*STRETCH_FACTOR], &S[j*STRETCH_FACTOR]);
    }
}


void __attribute__((aligned(4096))) do_ksa() {
    memset(S, 0, N*STRETCH_FACTOR); 
    KSA(key, KEY_SIZE, S);
}

static unsigned long next = 0;
int lcg(void) {
    next = next * 1103515245 + 12345;
    return((unsigned)(next/65536) % 32768);
}

void generate_key() {
    // set set for LCG
    next = SEED;

    for (int i = 0; i < KEY_SIZE; i++) {
        key[i] = lcg() % 256;
    }
}

void log_key() {
    FILE* fd = fopen(KEY_FILE, "w");
    for (int i = 0; i < KEY_SIZE; i++) {
        fprintf(fd, "%02x", key[i]);
    }
    fclose(fd);
}

int main() {
    generate_key();

    // victim call
    do_ksa();

    // log the key for postprocessing purposes
    log_key();
    return 0;
}
