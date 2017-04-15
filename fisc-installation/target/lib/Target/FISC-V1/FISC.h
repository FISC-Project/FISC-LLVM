//===-- FISC.h - Top-level interface for FISC representation --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the entry points for global functions defined in the LLVM
// FISC back-end.
//
//===----------------------------------------------------------------------===//

#ifndef TARGET_FISC_H
#define TARGET_FISC_H

#include "MCTargetDesc/FISCMCTargetDesc.h"
#include "llvm/Target/TargetMachine.h"

namespace llvm {
	class TargetMachine;
	class FISCTargetMachine;

	FunctionPass *createFISCISelDag(FISCTargetMachine &TM, CodeGenOpt::Level OptLevel);
} // end namespace llvm;

#endif
