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

FISCSubtarget::FISCSubtarget(const Triple &TT, StringRef CPU, StringRef FS,
                           FISCTargetMachine &TM)
    : FISCGenSubtargetInfo(TT, CPU, FS),
      DL("e-m:e-p:32:32-i1:8:32-i8:8:32-i16:16:32-i64:32-f64:32-a:0:32-n32"),
      InstrInfo(), TLInfo(TM), TSInfo(), FrameLowering() {}
