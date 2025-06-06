
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


def preprocessing(iteration=0, keysize=0):
    random_seed = random.randint(0, 2**32)
    with open(f"eval_data_square/seed_{keysize}_{iteration}.txt", "w") as f:
        f.write(str(random_seed))

    print(f"[-] Compiling with seed {random_seed}")
    compile_cmd = f"gcc examples/square_elf/main.c -DSEED={random_seed} -DKEYSIZE={keysize} -O0 -fcf-protection=none -ggdb -Wall -o examples/square_elf/main"
    compile_res = subprocess.run(["/bin/bash", "-c", compile_cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert compile_res.returncode == 0, "[!] Compilation failed"

    print("[-] Generating key.hex...")
    os.system("./examples/square_elf/main")
    assert os.path.exists("key.hex"), "[!] key.hex not found"
    os.system(f"mv key.hex eval_data_square/key_{keysize}_{iteration}.hex")

    print("[-] Tracing...")
    # trace the binary and generate ./cftrace.csv and ./dftrace.csv
    trace_res = subprocess.run(["/bin/bash", "-c", "python3 tracers/tracer-angr/main.py mod_exp_inner examples/square_elf/main"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert "Finished" in trace_res.stdout.decode(), "[!] Tracing failed"
    assert os.path.exists("./cftrace.csv"), "[!] Control-flow trace not found"
    assert os.path.exists("./dftrace.csv"), "[!] Data-flow trace not found"
    print("[-] Preprocessing done.")


def postprocessing(iteration=0, keysize=0):
    print("[-] Cleaning up...")
    os.system(f"mv examples/square_elf/main eval_data_square/main_{keysize}_{iteration}")
    os.system(f"mv cftrace.csv eval_data_square/cftrace_{keysize}_{iteration}")
    os.system(f"mv dftrace.csv eval_data_square/dftrace_{keysize}_{iteration}")

def solve(iteration=0, keysize=0):
    TARGET_PATH = "./examples/square_elf/main"
    CFTRACE_FILE = "./cftrace.csv"
    DFTRACE_FILE = "./dftrace.csv"
    TARGET_ECALL = "mod_exp"  # execution starts here
    TARGET_FUNC = "mod_exp_inner" # secret is symbolized are added here

    BINARY_BASE_ADDR = 0x0

    logging_enabled = True
    athena.IGNORE_LOWER_BITS = 0 # HARDCODED byte granularity
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

    secret_len = initial_state.regs.rdx.concrete_value
    secret = initial_state.solver.BVS("secret", secret_len * 8)  # bits -> bytes
    rsi_ptr = initial_state.regs.rsi.concrete_value

    # ATTENTION: this is a hack to fix the stack pointer
    rsp_offset_fix = initial_state.regs.rsp.concrete_value - 0x50
    initial_state.regs.rsp = rsp_offset_fix

    initial_state.memory.store(rsi_ptr, secret)

    athena_framework.set_initial_state(initial_state)

    start_time = time.time()
    athena_framework.run()
    run_time = time.time() - start_time
    start_time = time.time()
    solution = athena_framework.solve(secret)
    solve_time = time.time() - start_time
    solution_enc = f"{solution:064x}".replace("31", "1").replace("00", "0")
    return solution_enc, run_time, solve_time

if __name__ == "__main__":
    os.makedirs("eval_data_square", exist_ok=True)
    with open(f"eval_data_square/statistics.csv", "w") as f:
        f.write("keysize,iteration,run_time,solve_time,incorrect_bytes\n")
    for keysize in [1,2,4,8]:
        print(f"\n[+] Running with KEYSIZE={keysize}")
        for it in range(1):
            print(f"[+] Measuring iteration {it}")
            preprocessing(iteration=it, keysize=keysize)
            print(f"[-] Solving with keysize={keysize}")
            solution, run_time, solve_time = solve(keysize=keysize, iteration=it)
            with open(f"eval_data_square/key_{keysize}_{it}.hex", "rb") as f:
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
            postprocessing(iteration=it, keysize=keysize)
            print(f"")
            with open(f"eval_data_square/statistics.csv", "a") as f:
                f.write(f"{keysize},{it},{run_time},{solve_time},{incorrect_bytes}\n")
