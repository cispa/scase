#! /usr/bin/env python3

from tqdm import tqdm
from functools import partial

import angr
import claripy
import logging 

from engine import athena

TARGET_PATH = "../traces/jump-table/data_g01/main_12_0"
CFTRACE_FILE = "../traces/jump-table/data_g01/cftrace_12_0"
DFTRACE_FILE = "../traces/jump-table/data_g01/dftrace_12_0"
TARGET_ECALL = "do_something"  # execution starts here
TARGET_FUNC = "something" # secret is symbolized are added here

# take this from the tracer output
BINARY_BASE_ADDR = 0x0


def pause():
    print("Press key to continue...")
    input()

def solve():

    athena_framework = athena.AthenaFramework(
        TARGET_PATH, 
        TARGET_ECALL, 
        TARGET_FUNC,
        enable_control_flow_tracing=False,
        control_flow_tracefile=CFTRACE_FILE,
        enable_data_flow_tracing=True,
        data_flow_tracefile=DFTRACE_FILE,
        base_addr=BINARY_BASE_ADDR,
        target_is_enclave=False,
        verbose=True)

    #
    # Annotate the Secrets
    #
    initial_state = athena_framework.get_initial_state()

    # RDI points to the secret, hence symbolize that value
    # RSI is the length of the secret
    secret_len = initial_state.regs.rsi.concrete_value
    print(f"Secret length: {secret_len}")

    secret = initial_state.solver.BVS("secret", secret_len * 8)  # bits -> bytes

    rdi_ptr = initial_state.regs.rdi.concrete_value
    initial_state.memory.store(rdi_ptr, secret)

    rsp_offset_fix = initial_state.regs.rsp.concrete_value - 0x30
    initial_state.regs.rsp = rsp_offset_fix

    athena_framework.set_initial_state(initial_state)
    
    athena_framework.run()
    print("[+] Solving...")
    solution = athena_framework.solve(secret)
    solution_enc = solution.to_bytes(secret_len, byteorder='big')
    print(f"[+] Encoded solution: {solution_enc.decode()}")
    
if __name__ == "__main__":
    solve()

