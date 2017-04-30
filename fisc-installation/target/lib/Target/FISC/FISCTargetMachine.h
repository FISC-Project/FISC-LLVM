//===-- FISCTargetMachine.h - Define TargetMachine for FISC ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the FISC specific subclass of TargetMachine.
//
//===----------------------------------------------------------------------===//

#ifndef FISCTARGETMACHINE_H
#define FISCTARGETMACHINE_H

#include "FISC.h"
#include "FISCFrameLowering.h"
#include "FISCISelLowering.h"
#include "FISCInstrInfo.h"
#include "FISCSelectionDAGInfo.h"
#include "FISCSubtarget.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Target/TargetMachine.h"

namespace llvm {

class FISCTargetMachine : public LLVMTargetMachine {
    FISCSubtarget Subtarget;
    std::unique_ptr<TargetLoweringObjectFile> TLOF;

public:
    FISCTargetMachine(const Target &T, const Triple &TT, StringRef CPU,
                      StringRef FS, const TargetOptions &Options, Reloc::Model RM,
                      CodeModel::Model CM, CodeGenOpt::Level OL);
  
    const FISCSubtarget * getSubtargetImpl() const {
        return &Subtarget;
    }
  
    virtual const TargetSubtargetInfo * getSubtargetImpl(const Function &) const override {
        return &Subtarget;
    }

    /// Pass Pipeline Configuration
    virtual TargetPassConfig *createPassConfig(PassManagerBase &PM) override;
  
    TargetLoweringObjectFile *getObjFileLowering() const override {
        return TLOF.get();
    }
};
} // end namespace llvm

#endif
