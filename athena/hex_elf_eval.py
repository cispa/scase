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

CODE_PATH = "../victim-programs/jump-table"
STACK_OFFSET = 0x10

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


def preprocessing(iteration=0, ignore_lower_bits=0, keysize=1):
    random_seed = random.randint(0, 2**32)
    with open(f"eval_data_{keysize}/seed_{ignore_lower_bits}_{iteration}.txt", "w") as f:
        f.write(str(random_seed))

    print(f"[-] Compiling with seed {random_seed}")
    compile_cmd = f"gcc {CODE_PATH}/main.c -DSEED={random_seed} -DKEYSIZE={keysize} -O0 -fcf-protection=none -ggdb -Wall -o ./main"
    compile_res = subprocess.run(["/bin/bash", "-c", compile_cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert compile_res.returncode == 0, "[!] Compilation failed"

    print("[-] Generating key.hex...")
    os.system("./main")
    assert os.path.exists("key.hex"), "[!] key.hex not found"
    os.system(f"mv key.hex eval_data_{keysize}/key_{ignore_lower_bits}_{iteration}.hex")

    print("[-] Tracing...")
    # trace the binary and generate ./cftrace.csv and ./dftrace.csv
    trace_res = subprocess.run(["/bin/bash", "-c", "python3 tracers/tracer-angr/main.py something ./main"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert "Finished" in trace_res.stdout.decode(), "[!] Tracing failed"
    assert os.path.exists("./cftrace.csv"), "[!] Control-flow trace not found"
    assert os.path.exists("./dftrace.csv"), "[!] Data-flow trace not found"
    print("[-] Preprocessing done.")

def postprocessing(iteration=0, ignore_lower_bits=0, keysize=1):
    print("[-] Cleaning up...")
    os.system(f"mv main eval_data_{keysize}/main_{ignore_lower_bits}_{iteration}")
    os.system(f"mv cftrace.csv eval_data_{keysize}/cftrace_{ignore_lower_bits}_{iteration}")
    os.system(f"mv dftrace.csv eval_data_{keysize}/dftrace_{ignore_lower_bits}_{iteration}")

def solve(iteration=0, ignore_lower_bits=0, keysize=1):
    TARGET_PATH = "./main"
    CFTRACE_FILE = "./cftrace.csv"
    DFTRACE_FILE = "./dftrace.csv"
    TARGET_ECALL = "do_something"  # execution starts here
    TARGET_FUNC = "something" # secret is symbolized are added here

    BINARY_BASE_ADDR = 0x0

    logging_enabled = False
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

    # RDI points to the secret, hence symbolize that value
    # RSI is the length of the secret
    secret_len = initial_state.regs.rsi.concrete_value
    assert secret_len == keysize

    secret = initial_state.solver.BVS("secret", secret_len * 8)  # bits -> bytes

    rdi_ptr = initial_state.regs.rdi.concrete_value
    initial_state.memory.store(rdi_ptr, secret)

    rsp_offset_fix = initial_state.regs.rsp.concrete_value - STACK_OFFSET
    initial_state.regs.rsp = rsp_offset_fix

    athena_framework.set_initial_state(initial_state)

    start_time = time.time()
    athena_framework.run()
    run_time = time.time() - start_time
    start_time = time.time()
    solution = athena_framework.solve(secret)
    solve_time = time.time() - start_time
    solution_enc = solution.to_bytes(secret_len, byteorder='big')
    return solution_enc, run_time, solve_time

if __name__ == "__main__":
    for keysize in [2,4,8,16,32,64]:
        print(f"\nKEYSIZE = {keysize}")
        os.makedirs(f"eval_data_{keysize}", exist_ok=True)
        with open(f"eval_data_{keysize}/statistics.csv", "w") as f:
            f.write("ignored_bits,iteration,run_time,solve_time,incorrect_bytes\n")
        for bits in [0,12]:
            print(f"\n[+] Running with IGNORE_LOWER_BITS={bits}")
            for it in range(10):
                print(f"[+] Measuring iteration {it}")
                preprocessing(iteration=it, ignore_lower_bits=bits, keysize=keysize)
                print(f"[-] Solving with IGNORE_LOWER_BITS={bits}")
                solution, run_time, solve_time = solve(ignore_lower_bits=bits, iteration=it, keysize=keysize)
                with open(f"eval_data_{keysize}/key_{bits}_{it}.hex", "rb") as f:
                    key = f.read()
                incorrect_bytes = 0
                for i in range(len(key)):
                    if key[i] != solution[i]:
                        incorrect_bytes += 1
                if incorrect_bytes == 0:
                    log_success(f"Solution is correct")
                else:
                    log_warning(f"Solution is incorrect: {incorrect_bytes} bytes differ")
                    print(f"Solution: {solution}")
                    print(f"Recovered: {key}")
                print(f"[+] Finished in {run_time:.2f} seconds (run) and {solve_time:.2f} seconds (solve)")
                postprocessing(iteration=it, ignore_lower_bits=bits, keysize=keysize)
                print(f"")
                with open(f"eval_data_{keysize}/statistics.csv", "a") as f:
                    f.write(f"{bits},{it},{run_time},{solve_time},{incorrect_bytes}\n")
