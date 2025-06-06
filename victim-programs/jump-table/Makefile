SHELL = /bin/bash

all: main

main: main.c
        gcc main.c -DSEED=$$RANDOM -DKEYSIZE=$$KEYSIZE -O0 -fcf-protection=none -ggdb -Wall -o main

clean:
        rm -f main key.hex
