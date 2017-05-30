//===-- FISCSubtarget.cpp - FISC Subtarget Information ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the FISC specific subclass of TargetSubtargetInfo.
//
//===----------------------------------------------------------------------===//

#include "FISCSubtarget.h"
#include "FISC.h"
#include "llvm/Support/TargetRegistry.h"

#define DEBUG_TYPE "FISC-subtarget"

#define GET_SUBTARGETINFO_TARGET_DESC
#define GET_SUBTARGETINFO_CTOR
#include "FISCGenSubtargetInfo.inc"

using namespace llvm;

void FISCSubtarget::anchor() {}

FISCSubtarget::FISCSubtarget(const Triple &TT, StringRef CPU, StringRef FS, FISCTargetMachine &TM)
    : FISCGenSubtargetInfo(TT, CPU, FS),
      DL("E-p:64:64-i1:8:64-i8:8:64-i16:16:64-i32:32:64-f64:64-a:0:64-n64"),
      InstrInfo(), TLInfo(TM), TSInfo(), FrameLowering()
{
    InstrItins = getInstrItineraryForCPU(CPU);
}
