//===-- FISCRegisterInfo.cpp - FISC Register Information ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the FISC implementation of the MRegisterInfo class.
//
//===----------------------------------------------------------------------===//

#include "FISCRegisterInfo.h"
#include "FISC.h"
#include "FISCFrameLowering.h"
#include "FISCInstrInfo.h"
#include "FISCMachineFunctionInfo.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetFrameLowering.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"

#define GET_REGINFO_TARGET_DESC
#include "FISCGenRegisterInfo.inc"

using namespace llvm;

FISCRegisterInfo::FISCRegisterInfo() 
    : FISCGenRegisterInfo(FISC::LR) {}

const uint16_t * FISCRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
    static const uint16_t CalleeSavedRegs[] = { 
        FISC::X19, FISC::X20, FISC::X21,
        FISC::X22, FISC::X23, FISC::X24,
        FISC::X25, FISC::X26, FISC::X27, 0
    };
    return CalleeSavedRegs;
}

BitVector FISCRegisterInfo::getReservedRegs(const MachineFunction &MF) const {
    BitVector Reserved(getNumRegs());
    Reserved.set(FISC::SP);
    Reserved.set(FISC::LR);
    return Reserved;
}

const uint32_t *FISCRegisterInfo::getCallPreservedMask(const MachineFunction &MF, CallingConv::ID) const {
    return CC_Save_RegMask;
}

bool FISCRegisterInfo::requiresRegisterScavenging(const MachineFunction &MF) const {
    return true;
}

bool FISCRegisterInfo::trackLivenessAfterRegAlloc(const MachineFunction &MF) const {
    return true;
}

bool FISCRegisterInfo::useFPForScavengingIndex(const MachineFunction &MF) const {
    return false;
}

void FISCRegisterInfo::eliminateFrameIndex(MachineBasicBlock::iterator II,
                                           int SPAdj, unsigned FIOperandNum,
                                           RegScavenger *RS) const 
{
    MachineInstr           &MI   = *II;
    const MachineFunction  &MF   = *MI.getParent()->getParent();
    const MachineFrameInfo *MFI  = MF.getFrameInfo();
    MachineOperand         &FIOp = MI.getOperand(FIOperandNum);
    unsigned                FI   = FIOp.getIndex();

    /// Determine if we can eliminate the index from this kind of instruction.
    unsigned ImmOpIdx = 0;

    switch (MI.getOpcode()) {
    default:
        /// Not supported yet.
        return;
    case FISC::LDR:  case FISC::LDRB:  case FISC::LDRH:  case FISC::LDRSW:  case FISC::LDRXR:
    case FISC::LDRR: case FISC::LDRBR: case FISC::LDRHR: case FISC::LDRSWR: case FISC::LDRXRR:
    case FISC::STR:  case FISC::STRB:  case FISC::STRH:  case FISC::STRW:   case FISC::STRXR:
    case FISC::STRR: case FISC::STRBR: case FISC::STRHR: case FISC::STRWR:  case FISC::STRXRR:
        ImmOpIdx = FIOperandNum + 1;
        break;
    }

    // FIXME: check the size of offset.
    MachineOperand &ImmOp = MI.getOperand(ImmOpIdx);
    int Offset = MFI->getObjectOffset(FI) + MFI->getStackSize() + ImmOp.getImm();
    FIOp.ChangeToRegister(FISC::SP, false);
    ImmOp.setImm(Offset);
}

unsigned FISCRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
    return FISC::SP;
}
