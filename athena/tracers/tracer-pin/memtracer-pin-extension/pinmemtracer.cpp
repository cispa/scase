/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2018 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fstream>
#include <string>
#include <sstream>
#include <iostream>
#include <ios>
#include "unistd.h"

#include "pin.H"

std::ofstream memtrace;
std::ofstream iptrace;

// Print a memory read record
VOID RecordMemRead(VOID *ip, VOID *addr)
{
  // dumping the stringstream at once makes it thread-safe to write to the file
  std::ostringstream oss;
  oss << "0x" << std::hex << (size_t)addr << std::endl;
  memtrace << oss.str();
}

// Print a memory write record
VOID RecordMemWrite(VOID *ip, VOID *addr)
{
  // dumping the stringstream at once makes it thread-safe to write to the file
  std::ostringstream oss;
  oss << "0x" << std::hex << (size_t)addr << std::endl;
  memtrace << oss.str();
}

VOID printip(VOID *ip)
{
  // dumping the stringstream at once makes it thread-safe to write to the file
  std::ostringstream oss;
  oss << "0x" << std::hex << (size_t)ip << std::endl;
  iptrace << oss.str();
}


// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
  //record instructions
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);

  // Instruments memory accesses using a predicated call, i.e.
  // the instrumentation is called iff the instruction will actually be executed.
  //
  // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
  // prefixed instructions appear as predicated instructions in Pin.
  UINT32 memOperands = INS_MemoryOperandCount(ins);

  // Iterate over each memory operand of the instruction.
  for (UINT32 memOp = 0; memOp < memOperands; memOp++)
  {
    if (INS_MemoryOperandIsRead(ins, memOp))
    {
      INS_InsertPredicatedCall(
          ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
          IARG_INST_PTR,
          IARG_MEMORYOP_EA, memOp,
          IARG_END);
    }
    // Note that in some architectures a single memory operand can be
    // both read and written (for instance incl (%eax) on IA-32)
    // In that case we instrument it once for read and once for write.
    if (INS_MemoryOperandIsWritten(ins, memOp))
    {
      INS_InsertPredicatedCall(
          ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
          IARG_INST_PTR,
          IARG_MEMORYOP_EA, memOp,
          IARG_END);
    }
  }
}

VOID Fini(INT32 code, VOID *v)
{
  memtrace.close();
  iptrace.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
  PIN_ERROR("This Pintool prints a trace of memory and isnstruction adresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
  return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv))
    return Usage();

  memtrace.open("memory_trace.csv", std::ios_base::out | std::ios_base::trunc);
  iptrace.open("instruction_trace.csv", std::ios_base::out | std::ios_base::trunc);

  PIN_InitSymbols();

  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);

  // Never returns
  PIN_StartProgram();

  return 0;
}
