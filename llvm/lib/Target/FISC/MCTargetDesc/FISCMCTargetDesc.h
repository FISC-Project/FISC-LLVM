//===-- FISCMCTargetDesc.h - FISC Target Descriptions ---------*- C++ -*-===//
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

#ifndef FISCMCTARGETDESC_H
#define FISCMCTARGETDESC_H

#include "llvm/Support/DataTypes.h"

namespace llvm {

class Target;
class MCInstrInfo;
class MCRegisterInfo;
class MCSubtargetInfo;
class MCContext;
class MCCodeEmitter;
class MCAsmInfo;
class MCCodeGenInfo;
class MCInstPrinter;
class MCObjectWriter;
class MCAsmBackend;
class StringRef;
class raw_ostream;
class raw_pwrite_stream;
class Triple;

extern Target TheFISCTarget;

MCCodeEmitter  *createFISCMCCodeEmitter(const MCInstrInfo &MCII, const MCRegisterInfo &MRI, MCContext &Ctx);
MCAsmBackend   *createFISCAsmBackend(const Target &T, const MCRegisterInfo &MRI, const Triple &TT, StringRef CPU);
MCObjectWriter *createFISCELFObjectWriter(raw_pwrite_stream &OS, uint8_t OSABI);

} // end namespace llvm

/// Defines symbolic names for FISC registers.  This defines a mapping from register name to register number.
#define GET_REGINFO_ENUM
#include "FISCGenRegisterInfo.inc"

/// Defines symbolic names for the FISC instructions.
#define GET_INSTRINFO_ENUM
#include "FISCGenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "FISCGenSubtargetInfo.inc"

#endif
