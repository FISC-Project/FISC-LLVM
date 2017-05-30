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

namespace FISC {
enum CondCodes {
	COND_EQ = 1, // Equal (==)
	COND_NE = 2, // Not equal (!=)
	COND_LT = 3, // Lower (<)
	COND_LE = 4, // Lower or equal (<=)
	COND_GT = 5, // Greater (>)
	COND_GE = 6, // Greater or equal (>=)
	COND_INVAL = -1
};
}

class TargetMachine;
class FISCTargetMachine;

FunctionPass *createFISCISelDag(FISCTargetMachine &TM, CodeGenOpt::Level OptLevel);
FunctionPass *createFISCDelaySlotFillerPass(FISCTargetMachine &TM);
} // end namespace llvm

#endif
