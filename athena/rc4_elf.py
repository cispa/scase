#! /usr/bin/env python3

from tqdm import tqdm
from functools import partial

import angr
import claripy
import logging 

from engine import athena

TARGET_PATH = "../traces/rc4-ksa/victim"
CFTRACE_FILE = "../traces/rc4-ksa/cftrace.csv"
DFTRACE_FILE = "../traces/rc4-ksa/dftrace.csv"
TARGET_ECALL = "do_ksa"  # execution starts here
TARGET_FUNC = "KSA" # secret is symbolized are added here

STACK_OFFSET = 0x10

# take this from the tracer output
BINARY_BASE_ADDR = 0x0


def pause():
    print("Press key to continue...")
    input()

def solve():

    athena.IGNORE_LOWER_BITS = 0
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
        verbose=True)

    #
    # Annotate the Secrets
    #
    initial_state = athena_framework.get_initial_state()

    print(f"RDI: {initial_state.regs.rdi}")
    print(f"RSI: {initial_state.regs.rsi}")
    print(f"RDX: {initial_state.regs.rdx}")

    # secret len is encoded in RSI
    secret_len = initial_state.regs.rsi.concrete_value
    # secret is pointed to by RDI
    secret = initial_state.solver.BVS("secret", secret_len * 8)  # bits -> bytes
    initial_state.memory.store(initial_state.regs.rdi.concrete_value, secret)

    rsp_offset_fix = initial_state.regs.rsp.concrete_value - STACK_OFFSET
    initial_state.regs.rsp = rsp_offset_fix

    athena_framework.set_initial_state(initial_state)
    
    athena_framework.run()
    print("[+] Solving...")
    solution = athena_framework.solve(secret)
    print(f"[+] Encoded solution: {solution:064x}")
    
if __name__ == "__main__":
    solve()

