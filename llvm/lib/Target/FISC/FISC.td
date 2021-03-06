//===-- FISC.td - Describe the FISC Target Machine -------*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This is the top level entry point for the FISC target.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Target-independent interfaces which we are implementing
//===----------------------------------------------------------------------===//

include "llvm/Target/Target.td"

//===----------------------------------------------------------------------===//
// Descriptions
//===----------------------------------------------------------------------===//

include "FISCSchedule.td"
include "FISCRegisterInfo.td"
include "FISCInstrInfo.td"
include "FISCCallingConv.td"

def FISCInstrInfo : InstrInfo;

//===----------------------------------------------------------------------===//
// FISC processors supported.
//===----------------------------------------------------------------------===//

class Proc<string Name, list<SubtargetFeature> Features>
    : Processor<Name, FISCItineraries, Features>;

def : Proc<"generic", []>;

def FISCAsmParser : AsmParser {
    let ShouldEmitMatchRegisterName = 0;
}

//===----------------------------------------------------------------------===//
// Declare the target which we are implementing
//===----------------------------------------------------------------------===//

def FISC : Target {
    let InstructionSet  = FISCInstrInfo;
    let AssemblyParsers = [FISCAsmParser];
}
