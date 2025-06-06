all: main main-minlibc

main: main.c
	gcc main.c -ggdb -static -Os -I./openssl/include/ -L./openssl/ -lssl -lcrypto -o main

main-minlibc: main.c
	gcc main.c minlibc.c -DMINLIBC -ggdb -static -Os -I./openssl/include/ -L./openssl/ -lssl -lcrypto -o main-minlibc
	
clean:
	rm -f main main-minlibc
	