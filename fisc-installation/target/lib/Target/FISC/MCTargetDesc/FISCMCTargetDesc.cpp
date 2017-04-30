//===-- FISCMCTargetDesc.cpp - FISC Target Descriptions -----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides FISC specific target descriptions.
//
//===----------------------------------------------------------------------===//

#include "FISCMCTargetDesc.h"
#include "InstPrinter/FISCInstPrinter.h"
#include "FISCMCAsmInfo.h"
#include "llvm/MC/MCCodeGenInfo.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/TargetRegistry.h"

#define GET_INSTRINFO_MC_DESC
#include "FISCGenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "FISCGenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "FISCGenRegisterInfo.inc"

using namespace llvm;

static MCInstrInfo *createFISCMCInstrInfo() {
    MCInstrInfo *X = new MCInstrInfo();
    InitFISCMCInstrInfo(X);
    return X;
}

static MCRegisterInfo *createFISCMCRegisterInfo(const Triple &TT) {
    MCRegisterInfo *X = new MCRegisterInfo();
    InitFISCMCRegisterInfo(X, FISC::LR);
    return X;
}

static MCSubtargetInfo *createFISCMCSubtargetInfo(const Triple &TT, StringRef CPU, StringRef FS) {
    return createFISCMCSubtargetInfoImpl(TT, CPU, FS);
}

static MCAsmInfo *createFISCMCAsmInfo(const MCRegisterInfo &MRI, const Triple &TT) {
    return new FISCMCAsmInfo(TT);
}

static MCCodeGenInfo *createFISCMCCodeGenInfo(const Triple &TT, Reloc::Model RM, CodeModel::Model CM, CodeGenOpt::Level OL) {
    MCCodeGenInfo *X = new MCCodeGenInfo();
    if (RM == Reloc::Default)
        RM = Reloc::Static;
    if (CM == CodeModel::Default)
        CM = CodeModel::Small;
    if (CM != CodeModel::Small && CM != CodeModel::Large) {
        report_fatal_error("Target only supports CodeModel Small or Large");
    }

    X->initMCCodeGenInfo(RM, CM, OL);
    return X;
}

static MCInstPrinter * createFISCMCInstPrinter(const Triple &TT, unsigned SyntaxVariant,
                                               const MCAsmInfo &MAI, const MCInstrInfo &MII,
                                               const MCRegisterInfo &MRI) 
{
    return new FISCInstPrinter(MAI, MII, MRI);
}

/// Force static initialization.
extern "C" void LLVMInitializeFISCTargetMC() {
    /// Register the MC asm info.
    RegisterMCAsmInfoFn X(TheFISCTarget, createFISCMCAsmInfo);

    /// Register the MC codegen info.
    TargetRegistry::RegisterMCCodeGenInfo(TheFISCTarget, createFISCMCCodeGenInfo);

    /// Register the MC instruction info.
    TargetRegistry::RegisterMCInstrInfo(TheFISCTarget, createFISCMCInstrInfo);

    /// Register the MC register info.
    TargetRegistry::RegisterMCRegInfo(TheFISCTarget, createFISCMCRegisterInfo);

    /// Register the MC subtarget info.
    TargetRegistry::RegisterMCSubtargetInfo(TheFISCTarget, createFISCMCSubtargetInfo);

    /// Register the MCInstPrinter
    TargetRegistry::RegisterMCInstPrinter(TheFISCTarget, createFISCMCInstPrinter);

    /// Register the ASM Backend.
    TargetRegistry::RegisterMCAsmBackend(TheFISCTarget, createFISCAsmBackend);

    /// Register the MCCodeEmitter
    TargetRegistry::RegisterMCCodeEmitter(TheFISCTarget, createFISCMCCodeEmitter);
}
