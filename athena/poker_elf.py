#! /usr/bin/env python3

from tqdm import tqdm
from functools import partial

import angr
import claripy
import logging 
import time 

from engine import athena
from engine import exploration_technique
from engine import constants
from engine import utils

TARGET_PATH = "../TwoPlusTwoHandEvaluator/test"
CFTRACE_FILE = "./tracers/tracer-angr/cftrace.csv"
DFTRACE_FILE = "./tracers/tracer-angr/dftrace.csv"
TARGET_ECALL = "main"  # execution starts here
TARGET_FUNC = "LookupHand" # secret is symbolized are added here

# take this from the tracer output
BINARY_BASE_ADDR = 0x0


def pause():
    print("Press key to continue...")
    input()

def solve():

    gran = 0
    athena.IGNORE_LOWER_BITS = gran
    exploration_technique.IGNORE_LOWER_BITS = gran
    constants.IGNORE_LOWER_BITS = gran
    utils.IGNORE_LOWER_BITS = gran

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

    # rdi: ptr to card array (7 cards a 32bit each)
    secret_len = 7 * 32
    secret = initial_state.solver.BVS("secret", secret_len)
    rdi_ptr = initial_state.regs.rdi.concrete_value
    initial_state.memory.store(rdi_ptr, secret)

    athena_framework.set_initial_state(initial_state)
    
    time_before_exploration = time.time()
    athena_framework.run()
    time_after_exploration = time.time()
    time_delta_exploration = time_after_exploration - time_before_exploration

    time_before_solving = time.time()
    solution = athena_framework.solve(secret,to_bytes=True)
    time_after_solving = time.time()
    time_delta_solving = time_after_solving - time_before_solving

    card_array = list()
    for card_no in range(7):
        current_card = int.from_bytes(
            solution[card_no*4:card_no*4+4], "little")
        print(current_card)
        card_array.append(current_card)

    print("Reconstructed array:")
    print(",".join([f"{card}" for card in card_array])) 
    print(f"[+] Time used (exploration): {time_delta_exploration:.2f}s")
    print(f"[+] Time used (solving): {time_delta_solving:.2f}s")
    
    
if __name__ == "__main__":
    solve()

