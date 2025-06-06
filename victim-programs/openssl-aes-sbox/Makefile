all: victim

victim: victim.c ./openssl/crypto/aes/aes_core.c ./openssl/crypto/aes/aes_x86core.c
	gcc victim.c -static -O0 -ggdb -Wall -I./openssl/include/openssl/ -L./openssl/ -lcrypto -o victim

victim-rekeyed: victim-rekeyed.c ./openssl/crypto/aes/aes_core.c ./openssl/crypto/aes/aes_x86core.c
	gcc victim-rekeyed.c -static -O0 -ggdb -Wall -I./openssl/include/openssl/ -L./openssl/ -lcrypto -o victim-rekeyed

clean:
	rm -f victim-rekeyed
