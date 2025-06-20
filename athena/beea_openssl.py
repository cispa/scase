#! /usr/bin/env python3

from tqdm import tqdm
from functools import partial

import angr
import claripy
import logging 
import time
import sys

from engine import athena
from engine import exploration_technique
from engine import constants
from engine import utils


TARGET_PATH = "../traces/openssl-beea/victim"
CFTRACE_FILE = "../traces/openssl-beea/cftrace.csv"
DFTRACE_FILE = "../traces/openssl-beea/dftrace.csv"
TARGET_ECALL = "main"  # execution starts here
TARGET_FUNC = "BN_gcd" # secret is symbolized are added here

# this allows the python interpreter to work with larger numbers
sys.set_int_max_str_digits(1 << 16)

# take this from the tracer output
BINARY_BASE_ADDR = 0x0


def pause():
    print("Press key to continue...")
    input()

def solve():

    ignore_lower_bits = 12
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
        verbose=False)

    #
    # Annotate the Secrets
    #
    initial_state = athena_framework.get_initial_state()
    endness = initial_state.arch.memory_endness

    print(f"RDI: {initial_state.regs.rdi}")
    print(f"RSI: {initial_state.regs.rsi}")
    print(f"RDX: {initial_state.regs.rdx}")

    secret_bignum_ptr = initial_state.regs.rsi.concrete_value
    # the limb array (d) is directy at the beginning of the bignum struct:
    #   struct bignum_st {
    #   BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
    #                                * chunks. */
    #   int top;                    /* Index of last used d +1. */
    #   /* The next are internal book keeping for bn_expand. */
    #   int dmax;                   /* Size of the d array. */
    #   int neg;                    /* one if the number is negative */
    #   int flags;
    #   };
    limb_array_ptr = initial_state.memory.load(secret_bignum_ptr, 8, endness=endness)

    bignum_top_offset = 0x8
    number_limbs = initial_state.memory.load(
        secret_bignum_ptr + bignum_top_offset, 4, endness=endness).concrete_value
    limb_size_in_bits = 64

    split_secret = False
    if split_secret:
        print(f"Splitting secret into {number_limbs} limbs")
        for i in range(number_limbs):
            secret_size = limb_size_in_bits
            secret = initial_state.solver.BVS("secret", secret_size)
            initial_state.memory.store(limb_array_ptr + i * secret_size, secret)
    else:
        secret_size = number_limbs * limb_size_in_bits
        print(f"Secret size: {secret_size} bits")
        secret = initial_state.solver.BVS("secret", secret_size)
        initial_state.memory.store(limb_array_ptr, secret)

    initial_state.options.add(angr.options.SIMPLIFY_EXPRS)
    initial_state.options.add(angr.options.SIMPLIFY_CONSTRAINTS)
    initial_state.options.add(angr.options.SIMPLIFY_MERGED_CONSTRAINTS)
    initial_state.options.add(angr.options.SIMPLIFY_MEMORY_READS)
    initial_state.options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
    initial_state.options.add(angr.options.SIMPLIFY_EXIT_GUARD)
    initial_state.options.add(angr.options.SIMPLIFY_RETS)
    initial_state.options.add(angr.options.LAZY_SOLVES)

    initial_state.options.add(angr.options.SIMPLIFY_REGISTER_READS)
    initial_state.options.add(angr.options.SIMPLIFY_REGISTER_WRITES)

    initial_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    initial_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    initial_state.options.remove(angr.options.TRACK_CONSTRAINT_ACTIONS)
    initial_state.options.add(angr.options.MEMORY_SYMBOLIC_BYTES_MAP)

    starting_time = time.time()
    athena_framework.set_initial_state(initial_state)
    
    athena_framework.run()
    print("[+] Finished running...")

    print("[+] Solving...")
    solution = athena_framework.solve(secret)
    print(solution)
    finishing_time = time.time()
    
if __name__ == "__main__":
    solve()

