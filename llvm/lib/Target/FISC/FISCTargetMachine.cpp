//===-- FISCTargetMachine.cpp - Define TargetMachine for FISC -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "FISCTargetMachine.h"
#include "FISC.h"
#include "FISCFrameLowering.h"
#include "FISCInstrInfo.h"
#include "FISCISelLowering.h"
#include "FISCSelectionDAGInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetLoweringObjectFileImpl.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

static std::string computeDataLayout(const Triple &TT, StringRef CPU, const TargetOptions &Options) {
    return "E-p:64:64:64-i1:8:64-i8:8:64-i16:16:64-i32:32:64-f64:64-a:0:64-n64";
}

FISCTargetMachine::FISCTargetMachine(const Target &T, const Triple &TT,
                                     StringRef CPU, StringRef FS,
                                     const TargetOptions &Options,
                                     Reloc::Model RM, CodeModel::Model CM,
                                     CodeGenOpt::Level OL)
    : LLVMTargetMachine(T, computeDataLayout(TT, CPU, Options), TT, CPU, FS, Options, RM, CM, OL),
      Subtarget(TT, CPU, FS, *this),
      TLOF(make_unique<TargetLoweringObjectFileELF>()) 
{
    initAsmInfo();
}

namespace {
/// FISC Code Generator Pass Configuration Options.
class FISCPassConfig : public TargetPassConfig {
public:
    FISCPassConfig(FISCTargetMachine *TM, PassManagerBase &PM)
        : TargetPassConfig(TM, PM) {}

    FISCTargetMachine &getFISCTargetMachine() const {
        return getTM<FISCTargetMachine>();
    }

    virtual bool addPreISel()      override;
    virtual bool addInstSelector() override;
    virtual void addPreEmitPass()  override;
};
} // end of anonymous namespace

TargetPassConfig *FISCTargetMachine::createPassConfig(PassManagerBase &PM) {
    return new FISCPassConfig(this, PM);
}

bool FISCPassConfig::addPreISel() { 
    return false;
}

bool FISCPassConfig::addInstSelector() {
    addPass(createFISCISelDag(getFISCTargetMachine(), getOptLevel()));
    return false;
}

void FISCPassConfig::addPreEmitPass() {
    addPass(createFISCDelaySlotFillerPass(getFISCTargetMachine()));
}

/// Force static initialization.
extern "C" void LLVMInitializeFISCTarget() {
    RegisterTargetMachine<FISCTargetMachine> X(TheFISCTarget);
}
