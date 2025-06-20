#! /usr/bin/env python3


from tqdm import tqdm
from functools import partial

import angr
import claripy
import logging 

from engine import athena
from engine import exploration_technique
from engine import constants
from engine import utils


TARGET_PATH =  "../traces/openssl-aes-sbox/victim"
CFTRACE_FILE = "../traces/openssl-aes-sbox/cftrace.csv"
DFTRACE_FILE = "../traces/openssl-aes-sbox/dftrace.csv"
TARGET_ECALL = "main"  # execution starts here
TARGET_FUNC = "AES_encrypt" # secret is symbolized are added here

# take this from the tracer output
BINARY_BASE_ADDR = 0x0



def pause():
    print("Press key to continue...")
    input()
    
    
def print_key_diff(key1, key2, keylen):
    assert type(key1) == int
    assert type(key2) == int

    # add leading zeroes
    key1_bin = bin(key1)[2:].zfill(keylen)
    key2_bin = bin(key2)[2:].zfill(keylen)

    differing_bits = 0
    correct_bits = 0
    # we iterate from the back to the front, to prevent leading zero issues
    for i in range(keylen - 1, 0, -1):
        if key1_bin[i] != key2_bin[i]:
            differing_bits += 1
        else:
            correct_bits += 1
    
    print(f"[+] Number of correct bits: {correct_bits}/{keylen}")
    print(f"[+] Number of differing bits: {differing_bits}/{keylen}")
    
    
def solve():

    ignore_lower_bits = 0
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
        verbose=True)

    #
    # Annotate the Secrets
    #
    initial_state = athena_framework.get_initial_state()
    endness = initial_state.arch.memory_endness

    print(f"RDI: {initial_state.regs.rdi}")
    print(f"RSI: {initial_state.regs.rsi}")
    print(f"RDX: {initial_state.regs.rdx}")

    secret_len = 256  # bits
    secret = initial_state.solver.BVS("secret", secret_len)
    key_ptr = initial_state.regs.rdx.concrete_value
    
    initial_state.memory.store(key_ptr, secret)

    athena_framework.set_initial_state(initial_state)
    
    athena_framework.run()
    print("[+] Solving...")
    solution = athena_framework.solve(secret,check_constrained_bits=False)

    # just copy this from ./experiments/sbox-aes/victim.c
    actual_key_c_repr = '''
     0x51, 0x4d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 
		 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0xcc, 
		 0x4f, 0x6e, 0x9c, 0x2a, 0x15, 0x5f, 0x5f, 0x0b, 
		 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
    '''
    actual_key = actual_key_c_repr.replace("0x", "").replace(", ", "")
    actual_key = actual_key.replace("\n", "").replace(" ", "")
    actual_key = actual_key.replace("\t", "")
    print(f"[+] Recovered key: {solution:x}")
    print(f"[+] Actual key: {actual_key}")
    key_match = hex(solution)[2:] == actual_key
    print_key_diff(solution, int(actual_key, 16), secret_len)
    if key_match:
        print("[+] Keys match! Success!")
    else:
        print("[!] Key mismatch!")
    
if __name__ == "__main__":
    solve()

