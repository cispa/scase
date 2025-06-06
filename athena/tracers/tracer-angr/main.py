#! /usr/bin/env python3

import angr
import sys
import claripy
import logging
from functools import partial

CFTRACE_FILE = "./cftrace.csv"
DFTRACE_FILE = "./dftrace.csv"

#BINARY_BASE_ADDR = 0x555555554000
BINARY_BASE_ADDR = 0x0

ZEROED_LOWER_BITS = 0

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

dftrace = list()

def zero_lower_bits(addr, number_bits):
    mask = 1 << number_bits
    mask -= 1
    return addr & ~mask

def passthrough_file_on_disk(simgr, filename):
    with open(filename, "rb") as fd:
        content = fd.read()
    simfile = angr.storage.SimFile(filename, content)
    simgr.active[0].fs.insert(filename, simfile)

def advance_to_target_func(proj, target_func):

    target_func_addr = proj.loader.find_symbol(target_func).rebased_addr
    logger.info(f"[+] Target function: {target_func} @ 0x{target_func_addr:x}")

    base_func_addr = proj.loader.find_symbol("main").rebased_addr
    logger.info(f"[+] Base function: {'main'} @ 0x{base_func_addr:x}")

    initial_state = proj.factory.call_state(
        addr=base_func_addr,
        ret_addr=0x0
    )
    simgr = proj.factory.simgr(initial_state)

    simgr.run(until= lambda sm: sm.active[0].addr == target_func_addr)
    return simgr, simgr.active[0]

def dftrace_mem_callback(state, verbose, dftrace, is_mem_write_callback):
    if is_mem_write_callback:
        target_addr_is_concrete = state.inspect.mem_write_address.concrete
        if target_addr_is_concrete:
            accessed_addr = state.inspect.mem_write_address.concrete_value
            dftrace.append(accessed_addr)
    else:
        target_addr_is_concrete = state.inspect.mem_read_address.concrete
        if target_addr_is_concrete:
            accessed_addr = state.inspect.mem_read_address.concrete_value
            dftrace.append(accessed_addr)

def register_dataflow_callbacks(state):
    global dftrace
    # we register these callbacks in which the data flow trace is checked
    state.inspect.b('mem_write', when=angr.BP_BEFORE,
                    action=partial(dftrace_mem_callback, 
                                verbose=False,
                                dftrace=dftrace, 
                                is_mem_write_callback=True))
    state.inspect.b('mem_read', when=angr.BP_BEFORE,
                    action= partial(dftrace_mem_callback, 
                                verbose=False,
                                dftrace=dftrace, 
                                is_mem_write_callback=False))
    return state

def main():
    #
    # Initialization
    #
    if len(sys.argv) < 3:
        print(f"USAGE:\n\t {sys.argv[0]}: <TARGET_FUNC> <target-binary>")
        exit(0)
    target_func = sys.argv[1] 
    target_binary = sys.argv[2]
    

    proj = angr.Project(
        target_binary,
        auto_load_libs=False,
        load_options = {"main_opts": {"base_addr" : BINARY_BASE_ADDR}}
    )

    simgr, initial_state = advance_to_target_func(proj, target_func)
    initial_history = len(simgr.active[0].history.bbl_addrs)

    initial_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    initial_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    register_dataflow_callbacks(initial_state)

    initial_callstack_depth = len(initial_state.callstack)
    print(f"initial callstack depth: {initial_callstack_depth}")

    simgr.run(until=lambda sm: len(sm.active[0].callstack) < initial_callstack_depth)
    print(f"Finished at address: {simgr.active[0].addr:x}")
    bb_addresses = simgr.active[0].history.bbl_addrs.hardcopy

    with open("cftrace.csv", "w") as fd:
        fd.write("virt_addr;rip\n")

        for addr in bb_addresses[initial_history:]:
            bb_len = proj.factory.block(addr).instructions
            addr = zero_lower_bits(addr, ZEROED_LOWER_BITS)
            print(f"0x{addr:x} -> len {bb_len}")

            # we need to print the address for every instruction in the basic block
            for _ in range(bb_len):
                fd.write(f"0x{addr:x};0x0\n")
    
    with open("dftrace.csv", "w") as fd:
        fd.write("virt_addr;rip\n")
        for addr in dftrace:
            fd.write(f"0x{addr:x};0x0\n")
    

if __name__ == "__main__":
    main()
