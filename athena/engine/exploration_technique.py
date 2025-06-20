#! /usr/bin/env python3

import angr
import os
from engine.utils import *

class TraceGuidedExploration(angr.ExplorationTechnique):
    def __init__(self, 
                 enable_control_flow_tracing=False, control_flow_trace_list=None, 
                 enable_data_flow_tracing=False, data_flow_trace_list=None,
                 verbose=False):
        super().__init__()
        if enable_control_flow_tracing:
            assert(type(control_flow_trace_list) == list)
            assert(len(control_flow_trace_list) > 0)
            assert(type(control_flow_trace_list[0]) == TraceEntry)
        if enable_data_flow_tracing:
            assert(type(data_flow_trace_list) == list)
            assert(len(data_flow_trace_list) > 0)
            assert(type(data_flow_trace_list[0]) == TraceEntry)

        self.cftrace = control_flow_trace_list
        self.dftrace = data_flow_trace_list

        self.enable_cftracing = enable_control_flow_tracing
        self.enable_dftracing = enable_data_flow_tracing

        self.verbose = verbose
        self.step_counter = 0

    def is_rep_instr(self, state):
        current_instruction = state.block().capstone.insns[0]
        return "rep" in current_instruction.mnemonic

    def is_aligned_with_cftrace(self, state):
        trace_idx = state.globals["cf_step_counter"]
        current_addr = zero_lower_bits(state.addr, IGNORE_LOWER_BITS)
        if trace_idx >= len(self.cftrace):
            return False
        if self.verbose:
            # note that the tracer RIP is pointing to the *next* instruction
            # hence we calculate the RIP of the previous instruction
            if trace_idx > 0:
                tracer_rip = self.cftrace[trace_idx-1].rip
            else:
                tracer_rip = 0
            engine_rip = state.addr
            if tracer_rip != 0:
                print(f"RIP: 0x{engine_rip:x} -> 0x{current_addr:x} == 0x{self.cftrace[trace_idx].addr:x} (original RIP: 0x{tracer_rip:x})")
            else:
                print(f"RIP: 0x{engine_rip:x} -> 0x{current_addr:x} == 0x{self.cftrace[trace_idx].addr:x}")
            if tracer_rip != 0 and engine_rip != tracer_rip:
                logging.warning(f"  RIP mismatch: 0x{engine_rip:x} != 0x{tracer_rip:x}")

        # Note: while zeroing the lower bits of the CFtrace is not necessary for 
        # enclave traces (as they are paged aligned anyway, it makes the framework
        # capable of handling more fine granular traces, e.g., during the evaluation)
        return current_addr == zero_lower_bits(self.cftrace[trace_idx].addr, IGNORE_LOWER_BITS)

    def is_aligned_with_dftrace(self, state):
        return state.globals["aligned_with_dftrace"]
        
    def log_state_statistics(self, stashes):
        if not os.path.exists(STEPPING_STATISTICS_LOG_FNAME):
            with open(STEPPING_STATISTICS_LOG_FNAME, "w") as fd:
                fd.write("active-states;avoid-states\n")

        with open(STEPPING_STATISTICS_LOG_FNAME, "a") as fd:
            number_active_states = len(stashes.get('active', []))
            number_avoid_states = len(stashes.get('avoid', []))
            fd.write(f"{number_active_states};{number_avoid_states}\n")
        
    def step(self, simgr, stash='active', **kwargs):
        # Extract the states from the stash
        active_states = simgr.stashes[stash]
        
        new_active_states = list()
        new_avoid_states = list()
        new_finished_states = list()

        if LOG_STATISTICS:
            self.log_state_statistics(simgr.stashes)

        for state in active_states:
            state.history.trim()
            if self.verbose:
                print(f"State @ 0x{state.addr:x}")
            if state.regs.rip.concrete_value == 0x0:
                # this happens when we return from the highest function
                # i.e., when we return from the target function
                new_finished_states.append(state)
                continue

            valid_state = True
            do_not_step = False
            if self.enable_cftracing:
                # check whether the current state aligns with our trace
                # if not; we throw it away (i.e., into the 'avoid'-stash)
                if not self.is_aligned_with_cftrace(state):
                    if self.is_rep_instr(state):
                        # while rep instructions are a angr BasicBlock on their own,
                        # atleast the ptrace-trace is inaccurate for them.
                        # right now, we just use this hack as a workaround
                        # TODO: figure out why the trace is broken for them 
                        #   (wrong number of repetitions)
                        # we handle them by just ignoring the access

                        if self.verbose:
                            print(f"\tIgnoring REP instruction @ 0x{state.addr:x}")

                        # note that we do not increase the step counter for this instruction
                        assert(state.block().instructions == 1)
                        do_not_step = True

                    else:  # if self.is_rep_instr(state):
                        if self.verbose:
                            print(f"\tPruning state @ 0x{state.addr:x} (due to CF trace mismatch)")
                            print_basic_block_code(state.block())
                            if len(active_states) == 1:
                                print("Last state was pruned")
                                print_backtrace(state)
                                import IPython; IPython.embed()
                        valid_state = False
                        

                # we also need to increase the CF step counter
                # to make sure that the next step takes the next matching trace entry
                # note: this works as angr internally steps in size of its basic blocks
                # also note: angr BBs are not the same as "normal" BBs, 
                # e.g., angr starts a new BB after function calls, which is 
                # useful to make this code work without handling such corner cases
                if not do_not_step:
                    state.globals["cf_step_counter"] += state.block().instructions

            if self.enable_dftracing:
                if not self.is_aligned_with_dftrace(state):
                    if self.verbose:
                        print(f"\tPruning state @ 0x{state.addr:x} (due to DF trace mismatch)")
                    # note that the only case in which this can happen
                    # is when the trace ends before the execution does
                    valid_state = False
                # note that the cf_step_counter is increased directly in the 
                # callbacks to allow handling multiple memory requests during 
                # one cf_step
            
            if self.verbose and self.enable_cftracing:
                if self.step_counter % 1000 == 0:
                    print(f"State @ 0x{state.addr:x} (trace idx: {state.globals['cf_step_counter']})")
                
            if valid_state:
                new_active_states.append(state)
            else:
                new_avoid_states.append(state)


        # Update the state manager with our custom split
        simgr.stashes[stash] = new_active_states
        simgr.stashes['avoid'] = simgr.stashes.get('avoid', []) + new_avoid_states
        simgr.stashes['finished'] = simgr.stashes.get('finished', []) + new_finished_states
        
        # Call the parent step method
        if self.verbose:
            print(f"Remaining stashes: {simgr.stashes[stash]}")
        simgr.step(stash=stash, **kwargs)
    
    def filter(self, simgr, state, **kwargs):
        callstack_depth = len(state.callstack)
        if callstack_depth < state.globals["initial_callstack_depth"]:
            # in this case, we returned from the target function
            return "finished"

        if self.enable_cftracing:
            i = state.globals["cf_step_counter"]
            if i >= len(self.cftrace):
                return "finished"
