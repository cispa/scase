#! /usr/bin/env python3


from tqdm import tqdm
from functools import partial

import angr
import claripy
import logging 

from engine import athena

#ENCLAVE_PATH = "./examples/enclave/encl.so"
TARGET_PATH = "../traces/square-multiply/data_g4096/main_64_0"
CFTRACE_FILE = "../traces/square-multiply/data_g4096/cftrace_64_0"
DFTRACE_FILE = "../traces/square-multiply/data_g4096/dftrace_64_0"
TARGET_ECALL = "sgx_mod_exp"  # execution starts here
TARGET_FUNC = "mod_exp_inner" # secret is symbolized are added here

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
        enable_control_flow_tracing=True,
        control_flow_tracefile=CFTRACE_FILE,
        enable_data_flow_tracing=False,
        data_flow_tracefile=DFTRACE_FILE,
        base_addr=BINARY_BASE_ADDR,
        target_is_enclave=False,
        verbose=True)

    #
    # Annotate the Secrets
    #
    initial_state = athena_framework.get_initial_state()

    # rdi: base
    # rsi: exponent (secret we're trying to figure out)
    # rdx: len(exponent)
    # rcx: mod
    #initial_state.regs.rdi = claripy.BVV(0x3, 32)  # plaintext

    # RSI points to the secret, hence symbolize that value
    # RDX is the length of the secret
    secret_len = initial_state.regs.rdx.concrete_value
    secret = initial_state.solver.BVS("secret", secret_len * 8)  # bits -> bytes
    rsi_ptr = initial_state.regs.rsi.concrete_value
    initial_state.memory.store(rsi_ptr, secret)

    athena_framework.set_initial_state(initial_state)
    
    athena_framework.run()
    solution = athena_framework.solve(secret)
    solution_enc = f"{solution:064x}".replace("31", "1").replace("00", "0")
    print(f"[+] Encoded solution: {solution_enc}")
    
if __name__ == "__main__":
    solve()
