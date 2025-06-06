#! /usr/bin/env python3

import os
import random


def set_dir_and_exec(dir, cmd):
    os.system(f"cd {dir} && {cmd}")

def gen_key_string():
    key_bytes = [str(random.choice(range(256))) for _ in range(16)]
    print("[+] Generated key bytes: ", key_bytes)
    return ",".join(key_bytes)

def generate_new_victim():
    with open("./victim.c", "r") as fd_src:
        with open("./victim-rekeyed.c", "w") as fd_dst:
            for line in fd_src:
                if "---KEY BYTES---" in line:
                    key_string = gen_key_string()
                    line = "  " + key_string + "\n"
                else:
                    line = line
                fd_dst.write(line)
    
    set_dir_and_exec("./", "make victim-rekeyed")

def generate_trace():
    set_dir_and_exec("../framework/tracers/tracer-angr", "python3 ./main.py AES_encrypt ../../../sbox-aes/victim-rekeyed")
    

def recover_key():
    set_dir_and_exec("../framework/", "python3 ./aes_openssl.py")

def main():
    print("[+] Generating new victim...")
    generate_new_victim()

    print("[+] Generating new trace...")
    generate_trace()

    print("[+] Recovering key...")
    recover_key()


if __name__ == "__main__":
    main()
