//===-- FISCTargetInfo.cpp - FISC Target Implementation -----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "FISC.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

Target llvm::TheFISCTarget;

extern "C" void LLVMInitializeFISCTargetInfo() {
    RegisterTarget<Triple::fisc> X(TheFISCTarget, "fisc", "FISC");
}
