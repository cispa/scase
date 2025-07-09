
#! /usr/bin/env python3

from tqdm import tqdm
from functools import partial

import angr
import claripy
import logging
import os
import random
random.seed(0)
import subprocess
import time

from engine import athena
from engine import exploration_technique
from engine import constants
from engine import utils

EVAL_PREFIX = "aes_sbox"
EVAL_PATH = f"eval_data_{EVAL_PREFIX}"

OPENSSL_LIBCRYPTO_PATH = "../victim-programs/openssl-aes-sbox/openssl/libcrypto.a"
OPENSSL_LIBSSL_PATH = "../victim-programs/openssl-aes-sbox/openssl/libssl.a"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    VERBOSE = '\033[96m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log_warning(message):
    print(f"{bcolors.WARNING}[-] {message}{bcolors.ENDC}")

def log_success(message):
    print(f"{bcolors.OKGREEN}[+] {message}{bcolors.ENDC}")

def format_256bit(n):
    b = n.to_bytes(32, 'big')
    return ', '.join(f'0x{byte:02x}' for byte in b)

def preprocessing(iteration=0, ignore_lower_bits=0, keysize=1):
    random_seed = random.randint(0, 2**32)
    with open(f"{EVAL_PATH}_{keysize}/seed_{ignore_lower_bits}_{iteration}.txt", "w") as f:
        f.write(str(random_seed))

    with open("../victim-programs/openssl-aes-sbox/victim.c", "r") as fd_src:
      with open(f"{EVAL_PATH}_{keysize}/victim_{ignore_lower_bits}_{iteration}.c", "w") as fd_dst:
          for line in fd_src:
              if "---KEY BYTES---" in line:
                  key_string = format_256bit(random_seed)
                  line = "  " + key_string + "\n"
              else:
                  line = line
              fd_dst.write(line)

    with open(f"{EVAL_PATH}_{keysize}/key_{ignore_lower_bits}_{iteration}.hex", "w") as f:
      f.write(f"{random_seed:064x}\n")

    print(f"[-] Compiling with seed {random_seed}")
    compile_cmd = f"gcc {EVAL_PATH}_{keysize}/victim_{ignore_lower_bits}_{iteration}.c -static -O0 -ggdb -Wall -I../victim-programs/openssl-aes-sbox/openssl/include/ -L../victim-programs/openssl-aes-sbox/openssl/ -lcrypto -o victim"
    os.system(compile_cmd)
    compile_res = subprocess.run(["/bin/bash", "-c", compile_cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert compile_res.returncode == 0, "[!] Compilation failed"

    print("[-] Tracing...")
    # trace the binary and generate ./cftrace.csv and ./dftrace.csv
    trace_res = subprocess.run(["/bin/bash", "-c", "python3 tracers/tracer-angr/main.py AES_encrypt victim"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert "Finished" in trace_res.stdout.decode(), "[!] Tracing failed"
    assert os.path.exists("./cftrace.csv"), "[!] Control-flow trace not found"
    assert os.path.exists("./dftrace.csv"), "[!] Data-flow trace not found"
    print("[-] Preprocessing done.")


def postprocessing(iteration=0, ignore_lower_bits=0, keysize=1):
    print("[-] Cleaning up...")
    os.system(f"mv victim {EVAL_PATH}_{keysize}/victim_{ignore_lower_bits}_{iteration}")
    os.system(f"mv cftrace.csv {EVAL_PATH}_{keysize}/cftrace_{ignore_lower_bits}_{iteration}")
    os.system(f"mv dftrace.csv {EVAL_PATH}_{keysize}/dftrace_{ignore_lower_bits}_{iteration}")

def switch_endianess(bs):
    assert len(bs) % 4 == 0
    r = b''
    for i in range(0, len(bs), 4):
        for pos in [i+3,i+2,i+1,i]:
            r += int.to_bytes(bs[pos], 1, byteorder='big')
    return r

def solve(iteration=0, ignore_lower_bits=0, keysize=1):
    TARGET_PATH = "./victim"
    CFTRACE_FILE = "./cftrace.csv"
    DFTRACE_FILE = "./dftrace.csv" 
    TARGET_ECALL = "main"  # execution starts here
    TARGET_FUNC = "AES_encrypt" # secret is symbolized are added here

    BINARY_BASE_ADDR = 0x0

    logging_enabled = True
    athena.IGNORE_LOWER_BITS = ignore_lower_bits
    exploration_technique.IGNORE_LOWER_BITS = ignore_lower_bits
    utils.IGNORE_LOWER_BITS = ignore_lower_bits
    constants.IGNORE_LOWER_BITS = ignore_lower_bits
    athena_framework = athena.AthenaFramework(
        TARGET_PATH,
        TARGET_ECALL,
        TARGET_FUNC,
        enable_control_flow_tracing=True,
        control_flow_tracefile=CFTRACE_FILE,
        enable_data_flow_tracing=True,
        data_flow_tracefile=DFTRACE_FILE,
        base_addr=BINARY_BASE_ADDR,
        target_is_enclave=False,
        verbose=logging_enabled,
        suppress_all_logging=not logging_enabled)

    #
    # Annotate the Secrets
    #
    initial_state = athena_framework.get_initial_state()
    endness = initial_state.arch.memory_endness

    secret_len = 256  # bits
    secret = initial_state.solver.BVS("secret", secret_len)
    key_ptr = initial_state.regs.rdx.concrete_value
    
    initial_state.memory.store(key_ptr, secret)

    athena_framework.set_initial_state(initial_state)

    start_time = time.time()
    athena_framework.run()
    run_time = time.time() - start_time
    start_time = time.time()
    solution = athena_framework.solve(secret)
    solve_time = time.time() - start_time
    solution_enc = switch_endianess(solution.to_bytes(secret_len, byteorder='big'))
    return solution_enc, run_time, solve_time

if __name__ == "__main__":
    if not os.path.exists(OPENSSL_LIBCRYPTO_PATH) or not os.path.exists(OPENSSL_LIBSSL_PATH):
        log_warning("OpenSSL libraries not found. Please build OpenSSL first.")
        exit(1)
    for keysize in [256]:
        print(f"\nKEYSIZE = {keysize}")
        os.makedirs(f"{EVAL_PATH}_{keysize}", exist_ok=True)
        with open(f"{EVAL_PATH}_{keysize}/statistics.csv", "w") as f:
            f.write("ignored_bits,iteration,run_time,solve_time,incorrect_bits\n")
        for bits in [0,1,2,3,4,5,6,7,8,9,10,11,12]:
            print(f"\n[+] Running with IGNORE_LOWER_BITS={bits}")
            for it in range(10):
                print(f"[+] Measuring iteration {it}")
                preprocessing(iteration=it, ignore_lower_bits=bits, keysize=keysize)
                print(f"[-] Solving with IGNORE_LOWER_BITS={bits}")
                solution, run_time, solve_time = solve(ignore_lower_bits=bits, iteration=it, keysize=keysize)
                with open(f"{EVAL_PATH}_{keysize}/key_{bits}_{it}.hex", "rb") as f:
                    key = f.read()
                key = "514dab12ffddb332528fbb1dec45cecc4f6e9c2a155f5f0b25776b70cde2f780"
                key = bytes.fromhex(key)
                #key = bytes.fromhex(key.strip().decode('ascii'))
                #max_len = max(len(key), len(solution))
                #key = key.rjust(max_len, b'\x00')
                #solution = solution.rjust(max_len, b'\x00')
                key = key.strip(b"\x00")
                solution = solution.strip(b"\x00")
                key_bits = ''.join(f'{b:08b}' for b in key)
                solution_bits = ''.join(f'{b:08b}' for b in solution)
                diffs = [(i, x, y) for i, (x, y) in enumerate(zip(key_bits, solution_bits)) if x != y]
                if len(diffs) == 0:
                    log_success(f"Solution is correct")
                else:
                    log_warning(f"Solution is incorrect: {len(diffs)} bits differ")
                    print(f"athena: {solution}")
                    print(f"actual key: {key}")
                print(f"[+] Finished in {run_time:.2f} seconds (run) and {solve_time:.2f} seconds (solve)")
                postprocessing(iteration=it, ignore_lower_bits=bits, keysize=keysize)
                print(f"")
                with open(f"{EVAL_PATH}_{keysize}/statistics.csv", "a") as f:
                    f.write(f"{bits},{it},{run_time},{solve_time},{len(diffs)}\n")

