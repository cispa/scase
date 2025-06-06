#! /usr/bin/env python3

import angr
import logging
import claripy
import hashlib

from engine.constants import *

# =============================================================================    
#                              Helper functions
# =============================================================================    
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


def guardian_get_ecall_id_for_symbol(ecall_list, symbol_name):
    for ecall in ecall_list:
        # <ecall-id>, <ecall-symbol>, ...
        if ecall[1] == symbol_name:
            return ecall[0]
    return None

class TraceEntry:
    def __init__(self, addr, rip):
        self.addr = addr
        self.rip = rip

def read_tracefile(fname):
    # tracefile format:
    # <addr-of-trace>; <RIP-of-execution>
    # note: if the RIP is not available, it is set to 0
    trace = list()

    with open(fname, "r") as fd:
        lines = fd.readlines()
        if lines[0] != TRACE_FILE_HEADER:
            logging.error(f"Invalid tracefile header ({fname}): {lines[0]}")
            exit(1)
        for line in lines[1:]:
            addr, rip = line.split(";")
            trace.append(TraceEntry(int(addr, 0), int(rip, 0)))
    return trace

def zero_lower_bits(addr, number_bits):
    mask = 1 << number_bits
    mask -= 1
    return addr & ~mask

def bitvector_get_name(bv):
    return bv.args[0]

def print_basic_block_code(block):
    for insn in block.capstone.insns:
        print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
    
def get_file_hash(fname):
    with open(fname, "rb") as fd:
        return hashlib.sha256(fd.read()).hexdigest()

def is_sim_procedure(project, func_addr):
    cfg = project.analyses.CFGFast()
    function = cfg.kb.functions[func_addr]

    return function.is_simprocedure

def print_backtrace(state):
    print(" ========= Backtrace =========")
    for frame in state.callstack:
        func_sym = state.project.loader.find_symbol(frame.func_addr)
        if func_sym is not None:
            print(f"  0x{frame.func_addr:x}: {func_sym.name}")
        else:
            print(f"  0x{frame.func_addr:x}: -")
    print(" =============================")

def spawn_shell_on_breakpoint(state):
    print(f"Breakpoint triggered at 0x{state.addr:x}...")
    print("Spawning REPL shell...")
    import IPython; IPython.embed()


def revert_current_step(state):
    state.globals["cf_step_counter"] -= state.block().instructions

dump_file = None
file_no = 0

def rotate_dump_file(state):
    global dump_file
    global file_no
    if dump_file:
        dump_file.close()
    dump_file = open(f"./dump{file_no}", "w")
    file_no += 1
    revert_current_step(state)
    
def dump_rax(state):
    global dump_file
    assert dump_file is not None
    dump_file.write(f"{state.regs.rax.concrete_value}")
    dump_file.flush()
    revert_current_step(state)