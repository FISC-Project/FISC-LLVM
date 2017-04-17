//===-- FISCMachineFuctionInfo.h - FISC machine function info -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares FISC-specific per-machine-function information.
//
//===----------------------------------------------------------------------===//

#ifndef FISCMACHINEFUNCTIONINFO_H
#define FISCMACHINEFUNCTIONINFO_H

#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"

namespace llvm {

// Forward declarations
class Function;

/// FISCFunctionInfo - This class is derived from MachineFunction private
/// FISC target-specific information for each MachineFunction.
class FISCFunctionInfo : public MachineFunctionInfo {
public:
	FISCFunctionInfo()  {}
	~FISCFunctionInfo() {}
};
} // end namespace llvm

#endif // FISCMACHINEFUNCTIONINFO_H

