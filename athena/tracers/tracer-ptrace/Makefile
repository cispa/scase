all: main tracee

main: main.c ../common/elf.c ../common/elf.h
	gcc main.c ../common/elf.c -ggdb -lelf -Os -o tracer

tracee: tracee.c
	gcc tracee.c -static -Os -o tracee
	
clean:
	rm -f tracer tracee
	