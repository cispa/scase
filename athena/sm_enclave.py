#! /usr/bin/env python3

from tqdm import tqdm
from functools import partial

import angr
import sys
import time
import claripy
import logging 

from engine import athena

ENCLAVE_PATH = "./tracers/tracer-sgx/encl.so"
CFTRACE_FILE = "./tracers/tracer-sgx/cftrace.csv"
TARGET_ECALL = "sgx_mod_exp"
TARGET_FUNC = "mod_exp_inner"

# take this from the tracer output

ENCLAVE_BASE_ADDR = 0x7ffff6000000

# this allows the python interpreter to work with larger numbers 
sys.set_int_max_str_digits(1 << 16)

def pause():
    print("Press key to continue...")
    input()

def solve():
    athena.IGNORE_LOWER_BITS = 12

    athena_framework = athena.AthenaFramework(
        ENCLAVE_PATH, 
        TARGET_ECALL, 
        TARGET_FUNC,
        enable_control_flow_tracing=True,
        control_flow_tracefile=CFTRACE_FILE,
        base_addr=ENCLAVE_BASE_ADDR,
        verbose=True)

    #
    # Annotate the Secrets
    #
    initial_state = athena_framework.get_initial_state()

    # rdi: base
    # rsi: exponent (secret we're trying to figure out)
    # rdx: len(exponent)
    # rcx: mod

    # RSI points to the secret, hence symbolize that value
    # RDX is the length of the secret
    secret_len = initial_state.regs.rdx.concrete_value
    secret = initial_state.solver.BVS("secret", secret_len * 8)  # bits -> bytes
    rsi_ptr = initial_state.regs.rsi.concrete_value
    initial_state.memory.store(rsi_ptr, secret)

    athena_framework.set_initial_state(initial_state)
    
    time_before_exploration = time.time()
    athena_framework.run()
    time_after_exploration = time.time()
    time_delta_exploration = time_after_exploration - time_before_exploration

    time_before_solving = time.time()
    solution = athena_framework.solve(secret)
    time_after_solving = time.time()
    time_delta_solving = time_after_solving - time_before_solving

    solution_enc = f"{solution:064x}".replace("31", "1").replace("00", "0")
    solution_enc = solution_enc.zfill(secret_len)  # pad with zeros
    print(f"[+] Encoded solution: {solution_enc}")
    print(f"[+] Time used (exploration): {time_delta_exploration:.2f}s")
    print(f"[+] Time used (solving): {time_delta_solving:.2f}s")
    
if __name__ == "__main__":
    solve()

