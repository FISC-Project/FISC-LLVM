//===-- FISCSchedule.td - FISC Scheduling Definitions ------*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Functional units across FISC chips sets. Based on GCC/FISC backend files.
//===----------------------------------------------------------------------===//
def ALU : FuncUnit;

//===----------------------------------------------------------------------===//
// Instruction Itinerary classes used for FISC
//===----------------------------------------------------------------------===//
def IIAlu    : InstrItinClass;
def IILoad   : InstrItinClass;
def IIStore  : InstrItinClass;
def IIIW     : InstrItinClass;
def IIBranch : InstrItinClass;
def IICmp    : InstrItinClass;

def IIPseudo : InstrItinClass;

//===----------------------------------------------------------------------===//
// FISC instruction itineraries.
// http://llvm.org/docs/doxygen/html/structllvm_1_1InstrStage.html
//===----------------------------------------------------------------------===//
def FISCItineraries : ProcessorItineraries<[ALU], [], [
    InstrItinData<IIAlu    , [InstrStage<1, [ALU]>]>,
    InstrItinData<IILoad   , [InstrStage<1, [ALU]>]>,
    InstrItinData<IIStore  , [InstrStage<1, [ALU]>]>,
    InstrItinData<IIIW     , [InstrStage<1, [ALU]>]>,
    InstrItinData<IIBranch , [InstrStage<1, [ALU]>]>,
    InstrItinData<IICmp    , [InstrStage<1, [ALU]>]>
]>;
