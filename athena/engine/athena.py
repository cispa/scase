#! /usr/bin/env python3

import angr
import claripy
import logging
import guardian
import pickle
import json
import signal
import os
import sys
from functools import partial

from angr.concretization_strategies import SimConcretizationStrategySolutions
from engine.exploration_technique import TraceGuidedExploration
from engine.utils import *

logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)
#logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
#logging.getLogger('angr.storage').setLevel(logging.DEBUG)
#logging.getLogger('angr').setLevel(logging.DEBUG)


def killme():
    os.system('kill %d' % os.getpid())

class AthenaFramework:
        
    def __init__(self, target_path, target_ecall, target_func, 
                 target_is_enclave=True,
                 enable_control_flow_tracing=False, control_flow_tracefile=None, 
                 enable_data_flow_tracing=False, data_flow_tracefile=None, 
                 base_addr=0x400000,
                 enable_caching=False,
                 verbose=False,
                 suppress_all_logging=False):

        if target_is_enclave:
            self.proj, self.guard = self.init_guardian_engine(
                    target_path, 
                    target_ecall,
                    base_addr)
        else:
            self.proj = angr.Project(
                target_path,
                load_options = {"main_opts": {"base_addr" : base_addr}},
                auto_load_libs=False)
            self.guard = None
        
        # handle arguments
        self.target_is_enclave = target_is_enclave
        self.target_path = target_path
        self.verbose = verbose
        self.target_ecall = target_ecall

        self.enable_control_flow_tracing = enable_control_flow_tracing
        self.control_flow_tracefile = control_flow_tracefile
        self.cftrace = None

        self.enable_data_flow_tracing = enable_data_flow_tracing
        self.data_flow_tracefile = data_flow_tracefile
        self.dftrace = None
        
        if self.enable_control_flow_tracing:
            assert(type(control_flow_tracefile) is str)
            self.enable_control_flow_tracing = True
            # the tracer is responsible for starting at the correct function
            self.cftrace = read_tracefile(control_flow_tracefile)

        if self.enable_data_flow_tracing:
            assert(type(data_flow_tracefile) is str)
            self.enable_data_flow_tracing = True
            self.dftrace = read_tracefile(data_flow_tracefile)

        if suppress_all_logging:
            self.verbose = False
            logging.getLogger('engine.athena').setLevel(logging.CRITICAL)
            logging.getLogger('angr').setLevel(logging.CRITICAL)
            logging.getLogger('angr.sim_manager').setLevel(logging.CRITICAL)

        # We handle SIGINT and attach a IPython shell to the framework object
        # this allows the user to check the internal state of the framework hangs 
        if self.verbose:
            #signal.signal(signal.SIGINT, self.sigint_handler)
            pass
            

        # check if we can restore state from disk
        if enable_caching:
            if self.restore_progress_from_disk():
                logger.info("Restored progress from disk.")
                return

        # everything afterwards is only required if we cannot restore the state

        # create initial state object
        self.initial_state = self.advance_to_target_function(target_func)
        if enable_caching:
            self.save_progress_to_disk()


    def init_guardian_engine(self, enclave_path, target_ecall, base_addr = 0x400000):
        proj = angr.Project(
            enclave_path,
            load_options = {"main_opts": {"base_addr" : base_addr}}
        )

        proj.hook_symbol("sgx_is_outside_enclave", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())

        guard = guardian.Project(
            proj,
            find_missing_ecalls_or_ocalls=True,
            violation_check=False,
        )

        target_ecall_id = guardian_get_ecall_id_for_symbol(guard.ecalls, target_ecall)
        try:
            guard.set_target_ecall(target_ecall_id)
        except TypeError:
            logger.error(f"Target eCall '{target_ecall}' not found in enclave. Keep in mind that typical eCall names carry the prefix 'sgx_'.")
            raise RuntimeError
        target_ecall_addr = proj.loader.find_symbol(target_ecall).rebased_addr
        logger.info(f"[!] Target eCall: {target_ecall} @ 0x{target_ecall_addr:x}")

        return proj, guard


    def advance_to_target_function(self, target_func):
        target_func_addr = self.proj.loader.find_symbol(target_func)
        if target_func_addr is None:
            logger.error(f"Target function '{target_func}' not found in binary.")
            raise RuntimeError
        target_func_addr = target_func_addr.rebased_addr

        logger.info(f"[+] Target function: {target_func} @ 0x{target_func_addr:x}")

        # cut of sgx_ to find the *actual* function that we care about
        base_func_name = self.target_ecall.removeprefix("sgx_") 

        logger.info(f"[+] Searching for base function {base_func_name}")
        base_func_addr = self.proj.loader.find_symbol(base_func_name)
        if base_func_addr is None:
            logger.error(f"Base function '{base_func_name}' not found in binary.")
            raise RuntimeError
        base_func_addr = base_func_addr.rebased_addr
        logger.info(f"[+] Base function: {base_func_name} @ 0x{base_func_addr:x}")

        # we set the return address to 0x0 s.t., RIP=0x0 indicates that we
        # finished (see TraceGuidedExploration.filter())
        initial_state = self.proj.factory.call_state(addr=base_func_addr, 
                                                     ret_addr=0x0,
                                                     )
        simgr = self.proj.factory.simgr(initial_state)

        logger.info("[+] Starting exploration to reach target function...")
        if self.target_is_enclave:
            self.guard.simgr = simgr
            self.guard.simgr.run(until=lambda sm: sm.active[0].addr == target_func_addr)
            state = self.guard.simgr.active[0]
        else:
            self.simgr = simgr
            # execute symbolic engine until we reach the target function
            self.simgr.run(until=lambda sm: len(sm.active) == 0 or sm.active[0].addr == target_func_addr)
            if len(self.simgr.active) == 0:
                print(f"[-] Could not reach target function {target_func} (0x{target_func_addr:x})")
                raise RuntimeError
            state = self.simgr.active[0]

        logger.info(f"[+] Reached target function: {target_func}")
        return state


    def register_dataflow_callbacks(self, state):
        # we register these callbacks in which the data flow trace is checked
        state.inspect.b('mem_write', when=angr.BP_BEFORE,
                        action=partial(dftrace_mem_callback, 
                                    verbose=self.verbose,
                                    dftrace=self.dftrace, 
                                    target_is_enclave=self.target_is_enclave,
                                    is_mem_write_callback=True))
        state.inspect.b('mem_read', when=angr.BP_BEFORE,
                        action= partial(dftrace_mem_callback, 
                                    verbose=self.verbose,
                                    dftrace=self.dftrace, 
                                    target_is_enclave=self.target_is_enclave,
                                    is_mem_write_callback=False))
        return state
    
    def register_fork_callback(self, state):
        # we register this callback to get verbose information about forks
        state.inspect.b('fork', when=angr.BP_AFTER, 
                        action=fork_callback)
        return state
    
    def start_cftrace_at_target_function(self, cftrace, target_func):
        target_func_addr = self.proj.loader.find_symbol(target_func).rebased_addr

        # we search for the first occurence of the target func and cut off
        # everything before that
        cut_off_idx = 0
        for entry in cftrace:
            if entry.addr == target_func_addr:
                break
            cut_off_idx += 1
        return cftrace[cut_off_idx:]
        

    def start_dftrace_at_target_function(self, target_func):
        target_func_addr = self.proj.loader.find_symbol(target_func).rebased_addr


    def get_initial_state(self):
        return self.initial_state


    def set_initial_state(self, state):
        self.initial_state = state


    def init_internal_state_objects(self, state):
        # we use these globals to keep track of the current position in the traces

        if self.enable_control_flow_tracing:
            # - keep track of the current index in the control flow trace
            state.globals["cf_step_counter"] = 0

        if self.enable_data_flow_tracing:
            # - keep track of the current index in the data flow trace
            state.globals["df_step_counter"] = 0

            # - mark states that violate the data flow trace 
            #   (marking is done in memory callbacks)
            state.globals["aligned_with_dftrace"] = True

            # register the callbacks for the data flow trace
            self.register_dataflow_callbacks(state)

            # register the callback for fork events to print verbose infos
            if self.verbose:
                self.register_fork_callback(state)
        
        if LOG_STATISTICS:
            if os.path.exists(STEPPING_STATISTICS_LOG_FNAME):
                os.remove(STEPPING_STATISTICS_LOG_FNAME)

        # we use this to keep track of when we return from the target function
        state.globals["initial_callstack_depth"] = len(state.callstack)

        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        #state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

        # when reading/writing symbolic memory, angr will concretize the values.
        # However, the default stategies only pick one solution. For our approach
        # to work, we want all (limited to N) possible solutions, this, for example,
        # allows us to correctly handle symbolic values for jumptables
        strategy = SimConcretizationStrategySolutions(MAX_CONCRETIZATION_SOLUTIONS) 
        state.memory.read_strategies = [strategy]
        state.memory.write_strategies = [strategy]
        
        if self.target_is_enclave:
            self.guard.simgr.active[0] = self.guard.simgr.active[0].copy()
            self.guard.simgr.active[0].options.remove(angr.sim_options.COPY_STATES)
        else:
            self.simgr.active[0] = self.simgr.active[0].copy()
            self.simgr.active[0].options.remove(angr.sim_options.COPY_STATES)

        self.simgr.active[0].options.add(angr.options.DOWNSIZE_Z3)
        self.simgr.active[0].options.add(angr.options.SIMPLIFY_EXPRS)
        self.simgr.active[0].options.add(angr.options.MEMORY_SYMBOLIC_BYTES_MAP)
        self.simgr.active[0].options.add(angr.options.SIMPLIFY_CONSTRAINTS)
        self.simgr.active[0].options.add(angr.options.TRACK_MEMORY_ACTIONS)
        self.simgr.active[0].options.add(angr.options.SIMPLIFY_EXPRS)

        return state
        

    def run(self, initial_state=None):
        if initial_state is None:
            # if the user provided no state, we take our internal one
            initial_state = self.initial_state

        initial_state = self.init_internal_state_objects(initial_state)

        simgr = self.proj.factory.simgr(initial_state)
        simgr.use_technique(TraceGuidedExploration(
            self.enable_control_flow_tracing, self.cftrace,
            self.enable_data_flow_tracing, self.dftrace,
            self.verbose))

        simgr.found = []

        if self.target_is_enclave:
            self.guard.simgr = simgr

            self.guard.simgr.run()
        else:
            self.simgr = simgr
            self.simgr.run()


    def count_constrainted_bits(self, solver, bitvector):
        constrained_bits = 0
        for i in range(len(bitvector)):
            # check if there are one or two possible solutions
            if len(solver.eval_upto(bitvector[i], 2)) == 1:
                constrained_bits += 1
        return constrained_bits
    

    def solve(self, bitvector, to_bytes=False, check_constrained_bits=False,
              enable_constraint_storing=False):
        if self.target_is_enclave:
            simgr = self.guard.simgr
        else:
            simgr = self.simgr

        if self.verbose:
            print("= Available stash count =")
            for s in simgr.stashes:
                print(f"  {s:15} ->\t{len(simgr.stashes[s])}")
            print("")
        if len(simgr.finished) == 0:
            logger.error("No finished state found. Is something wrong with the trace?")
            raise RuntimeError

        for state in simgr.finished:

            if enable_constraint_storing:
                # check if there are constraints stored
                # if yes, load them
                if os.path.exists(STORED_CONSTRAINTS_FNAME):
                    stored_constraints = pickle.load(
                        open(STORED_CONSTRAINTS_FNAME, "rb"))
                    state.solver.add(*stored_constraints)

            if to_bytes:
                solution = state.solver.eval(bitvector, cast_to=bytes)
                logger.info(f"{bitvector_get_name(bitvector)}:\t\t{solution}")

                if check_constrained_bits:
                    constrained_bits = self.count_constrainted_bits(state.solver, bitvector)
                    print(f"{bitvector_get_name(bitvector)} (contrained bits):\t\t{constrained_bits}/{len(bitvector)}")
            else:
                solution = state.solver.eval(bitvector)
                print(f"{bitvector_get_name(bitvector)}:\t\t{solution}")
                print(f"{bitvector_get_name(bitvector)} (hex):\t0x{solution:x}")

                if check_constrained_bits:
                    constrained_bits = self.count_constrainted_bits(state.solver, bitvector)
                    print(f"{bitvector_get_name(bitvector)} (contrained bits):\t\t{constrained_bits}/{len(bitvector)}")
            
            if enable_constraint_storing:
                # store current constraints to disk
                pickle.dump(state.solver.constraints, 
                            open(STORED_CONSTRAINTS_FNAME, "wb"))
            
            if check_constrained_bits:
                return solution, constrained_bits
            else:
                return solution


    def sigint_handler(self, signum, frame):
        print("[!] Stopping Execution...)\n"
              "[!] Providing a debug shell...\n"
              "[!] If you want to exit, execute: killme()\n")
        if not "IPython" in sys.modules:
            import IPython
        IPython.embed()
    

    def save_progress_to_disk(self):
        with open(STORED_PROGRESS_STATE_FNAME, "wb") as fd:
            pickle.dump(self, fd)

        # we also store the hashes of the traces and the binary to make sure
        # that we only restore cached state when nothing has changed
        meta_infos = dict()
        target_hash = get_file_hash(self.target_path)
        meta_infos["target_hash"] = target_hash

        cftrace_hash = get_file_hash(self.control_flow_tracefile)
        meta_infos["cftrace_hash"] = cftrace_hash

        dftrace_hash = get_file_hash(self.data_flow_tracefile)
        meta_infos["dftrace_hash"] = dftrace_hash

        json.dump(meta_infos, open(STORED_PROGRESS_META_FNAME, "w"))


    def remove_progress_from_disk(self):
        if os.path.exists(STORED_PROGRESS_STATE_FNAME):
            os.remove(STORED_PROGRESS_STATE_FNAME)
        if os.path.exists(STORED_PROGRESS_META_FNAME):
            os.remove(STORED_PROGRESS_META_FNAME)

    def restore_progress_from_disk(self):
        # returns True if progress was restored, False otherwise

        if not os.path.exists(STORED_PROGRESS_STATE_FNAME):
            return False
        if not os.path.exists(STORED_PROGRESS_META_FNAME):
            return False

        meta_infos = json.load(open(STORED_PROGRESS_META_FNAME, "rb"))
        
        # first check whether everything is still the same
        if meta_infos["target_hash"] != get_file_hash(self.target_path):
            logger.info("Target binary has changed. Cannot restore progress.")
            self.remove_progress_from_disk()
            return False

        if meta_infos["cftrace_hash"] != get_file_hash(self.control_flow_tracefile):
            logger.info("CFTrace has changed. Cannot restore progress.")
            self.remove_progress_from_disk()
            return False

        if meta_infos["dftrace_hash"] != get_file_hash(self.data_flow_tracefile):
            logger.info("DFTrace has changed. Cannot restore progress.")
            self.remove_progress_from_disk()
            return False

        # everything stayed the same, we can restore our progress
        with open(STORED_PROGRESS_STATE_FNAME, "rb") as fd:
            restored_framework = pickle.load(fd)
            self.initial_state = restored_framework.initial_state
            self.cftrace = restored_framework.cftrace
            self.dftrace = restored_framework.dftrace
            self.proj = restored_framework.proj
            self.guard = restored_framework.guard
        return True
        

def mark_illegal_dfstate(state):
    state.globals["aligned_with_dftrace"] = False


def get_current_instruction(state):
    for inst in state.block().capstone.insns:
        if inst.address == state.addr:
            return inst
def get_previous_instruction(state):
    # the previous instruction is either in the current or the previous BB
    # the previous *and* current BB are the last two BB history entries
    instructions = list()
    block_hist = state.history.bbl_addrs
    if len(block_hist) > 1:
        instructions += state.project.factory.block(block_hist[-2]).capstone.insns
    instructions += state.project.factory.block(block_hist[-1]).capstone.insns
    
    prev_instr = None
    for inst in instructions:
        if inst.address == state.addr:
            return prev_instr
        prev_instr = inst
    
    
def addr_belongs_to_stack(state, accessed_addr):
    stack_ptr = state.solver.eval(state.regs.sp)
    return stack_ptr <= \
            accessed_addr <= stack_ptr + state.solver.eval(state.arch.initial_sp)
    
    
def is_solvable_mem_access(accessed_addr, expected_addr):
    solver = claripy.SolverComposite()
    solver.add(accessed_addr >> IGNORE_LOWER_BITS 
           == expected_addr >> IGNORE_LOWER_BITS)
    return solver.satisfiable()


data_constraint_counter_writes = 0
data_constraint_counter_reads = 0
def log_dataflow_statistics(is_write_access):
    global data_constraint_counter_writes
    global data_constraint_counter_reads
    if is_write_access:
        data_constraint_counter_writes += 1
    else:
        data_constraint_counter_reads += 1
    if not os.path.exists(DATA_CONSTRAINTS_STATISTICS_LOG_FNAME):
        with open(DATA_CONSTRAINTS_STATISTICS_LOG_FNAME, "w") as fd:
            fd.write("data-constraints-added-read;data-constraints-added-write\n")

    with open(DATA_CONSTRAINTS_STATISTICS_LOG_FNAME, "a") as fd:
        fd.write(f"{data_constraint_counter_reads};{data_constraint_counter_writes}\n")

def dftrace_mem_callback(state, verbose, dftrace, target_is_enclave,
                        is_mem_write_callback):
    # we gather the address and whether the target is already concrete
    # i.e., if we depend on a symbolic value, like a secret key, the 
    # memory addresses may also be symbolic
    if is_mem_write_callback:
        target_addr_is_concrete = state.inspect.mem_write_address.concrete
        if target_addr_is_concrete:
            accessed_addr = state.inspect.mem_write_address.concrete_value
    else:
        target_addr_is_concrete = state.inspect.mem_read_address.concrete
        if target_addr_is_concrete:
            accessed_addr = state.inspect.mem_read_address.concrete_value

    if target_is_enclave and state.block().capstone.insns[0].mnemonic == "endbr64":
        # This is a workaround for a weird issue with function calls in angr:
        # angr adds an artificial read from the stack to the beginning of functions
        # that is not present in the trace.
        # Note: according to my (dwe) tests, this happens independant of what
        # the first instruction is. Hence,
        # **THIS WORKAROUND BREAKS IF** a function does not start with ENDBR64.
        # Update: it seems to only be a problem when guardian is used, 
        #   hence we only apply this workaround for enclaves
        # also see guardian/breakpoints.py:Breakpoints.setup()
        return

    # for debug purposes, we check for offsets of the engine RIP and the tracer RIP
    # note that the trace RIP points to the *next* instruction
    # whereas the engine RIP points to the current instruction
    trace_rip = dftrace[state.globals["df_step_counter"]].rip
    if trace_rip != 0:
        actual_rip = state.addr
        expected_rip = trace_rip - get_current_instruction(state).size
        if verbose:
            # TODO: our RIP calculation breaks on CALL/RET instructions
            is_ret_inst = get_current_instruction(state).mnemonic == "ret"
            is_call_inst = get_current_instruction(state).mnemonic == "call"
            if actual_rip != expected_rip and not is_ret_inst and not is_call_inst:
                logging.warning(f"  RIP mismatch (Mem Access): 0x{actual_rip:x} != 0x{expected_rip:x} (trace RIP: 0x{trace_rip:x})")
                logging.warning("  This is either a wrong trace or a bug in the engine.")

    # get the expected address from the data flow trace
    df_trace_idx = state.globals["df_step_counter"]
    if df_trace_idx < len(dftrace):
        expected_addr = dftrace[df_trace_idx].addr
        # increase the dataflow step counter to enable further checks
        state.globals["df_step_counter"] += 1
    else:
        # when there are no more expected data flow accesses
        # out of bounds, hence mark the state as illegal and exit early
        logging.error(f"{state.addr:x}: Data flow trace exhausted.")
        mark_illegal_dfstate(state)
        return
    
    # for concrete addresses, check whether we are on the stack
    if target_addr_is_concrete:
        # we currently ignore stack accesses as it's annoying and error-prone 
        # to align them correctly
        target_addr_is_on_stack = addr_belongs_to_stack(state, accessed_addr)
        if target_addr_is_on_stack:
            return

    # iirc it was important to duplicate that code as a variable assignment
    # didn't work for state.inspect.mem_(write/read)_address
    # TODO: double check and merge the code if possible
    if is_mem_write_callback:
        # we only check the new constraint for satisfiability to prevent
        # checking the entire set of constraints, as this doesn't scale well
        if not is_solvable_mem_access(state.inspect.mem_write_address, expected_addr):
            if verbose:
                logging.error(f"{state.addr:x}: Constraints no longer satisfiable! (trace idx: {df_trace_idx})")
                logging.error(f"  {state.inspect.mem_write_address} != 0x{expected_addr:x}")
            mark_illegal_dfstate(state)
            return
        state.solver.add(state.inspect.mem_write_address >> IGNORE_LOWER_BITS 
                         == expected_addr >> IGNORE_LOWER_BITS)
        log_dataflow_statistics(True)
        if verbose and target_addr_is_concrete:
            print(f"0x{state.addr:x}: Adding constraint (trace-idx: {df_trace_idx}): "
                  f"{zero_lower_bits(state.inspect.mem_write_address, IGNORE_LOWER_BITS)}"
                  f" == 0x{zero_lower_bits(expected_addr, IGNORE_LOWER_BITS):x}")
    else:
        # we only check the new constraint for satisfiability to prevent
        # checking the entire set of constraints, as this doesn't scale well
        if not is_solvable_mem_access(state.inspect.mem_read_address, expected_addr):
            if verbose:
                logging.error(f"{state.addr:x}: Constraints no longer satisfiable! (trace idx: {df_trace_idx})")
                logging.error(f"  {state.inspect.mem_read_address} != 0x{expected_addr:x}")
            mark_illegal_dfstate(state)
            return
        state.solver.add(state.inspect.mem_read_address >> IGNORE_LOWER_BITS 
                         == expected_addr >> IGNORE_LOWER_BITS)
        log_dataflow_statistics(False)
        if verbose and target_addr_is_concrete:
            print(f"0x{state.addr:x}: Adding constraint (trace-idx: {df_trace_idx}): "
                  f"{zero_lower_bits(state.inspect.mem_read_address, IGNORE_LOWER_BITS)}"
                  f" == 0x{zero_lower_bits(expected_addr, IGNORE_LOWER_BITS):x}")

    # TODO: commented out for performance reasons
    ## check if we added an impossible constraint
    #if not state.solver.satisfiable():
    #    if verbose:
    #        logging.error(f"{state.addr:x}: Constraints no longer satisfiable! (trace idx: {df_trace_idx})")
    #    mark_illegal_dfstate(state)


def fork_callback(state):
    # just used for more verbose infos
    predecessor_addr = state.history.bbl_addrs.hardcopy[-1]
    print(f"{bcolors.OKBLUE}0x{state.addr:x}: Forked off state from 0x{predecessor_addr:x}.{bcolors.ENDC}")
    state.globals["fork_parent"] = predecessor_addr

