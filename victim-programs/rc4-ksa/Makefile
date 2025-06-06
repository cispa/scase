SHELL = /bin/bash

all: main

main: main.c 
	gcc main.c -DSEED=$$RANDOM -fcf-protection -O0 -ggdb -Wall -o main

clean:
	rm -f main key.hex
