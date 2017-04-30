//===-- FISCFrameLowering.cpp - Frame info for FISC Target --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "FISCFrameLowering.h"
#include "FISC.h"
#include "FISCInstrInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Target/TargetLowering.h"
#include "llvm/Target/TargetOptions.h"
#include <algorithm> // std::sort

using namespace llvm;

//===----------------------------------------------------------------------===//
// FISCFrameLowering:
//===----------------------------------------------------------------------===//
FISCFrameLowering::FISCFrameLowering()
    : TargetFrameLowering(TargetFrameLowering::StackGrowsDown, 8, 0) {}
    
bool FISCFrameLowering::hasFP(const MachineFunction &MF) const {
    return MF.getTarget().Options.DisableFramePointerElim(MF) ||
           MF.getFrameInfo()->hasVarSizedObjects();
}

uint64_t FISCFrameLowering::computeStackSize(MachineFunction &MF) const {
    MachineFrameInfo *MFI = MF.getFrameInfo();
    uint64_t StackSize = MFI->getStackSize();
    unsigned StackAlign = getStackAlignment();
    if (StackAlign > 0)
        StackSize = RoundUpToAlignment(StackSize, StackAlign);
    return StackSize;
}

/// Materialize an offset for a ADD/SUB stack operation.
/// Return zero if the offset fits into the instruction as an immediate,
/// or the number of the register where the offset is materialized.
static unsigned materializeOffset(MachineFunction &MF, MachineBasicBlock &MBB,
                                  MachineBasicBlock::iterator MBBI,
                                  unsigned Offset) 
{
    const TargetInstrInfo &TII = *MF.getSubtarget().getInstrInfo();
    DebugLoc dl = MBBI != MBB.end() ? MBBI->getDebugLoc() : DebugLoc();
    const uint64_t MaxSubImm = 0xfff;
    if (Offset <= MaxSubImm) {
        /// The stack offset fits in the ADD/SUB instruction.
        return 0;
    } else {
        /// The stack offset does not fit in the ADD/SUB instruction.
        /// Materialize the offset using MOVZ+MOVK.
        unsigned OffsetReg = FISC::X9;
        unsigned OffsetQ1 = (unsigned)(Offset & 0xffff);
        unsigned OffsetQ2 = (unsigned)((Offset & 0xffff0000) >> 16);
        unsigned OffsetQ3 = (unsigned)((Offset & 0xffff00000000) >> 32);
        unsigned OffsetQ4 = (unsigned)((Offset & 0xffff000000000000) >> 48);

        /// FIXME: ADD THE LSL OPERANDS!!

        /// Build MOVK:
        BuildMI(MBB, MBBI, dl, TII.get(FISC::MOVZ), OffsetReg)
            .addImm(OffsetQ1)
            .setMIFlag(MachineInstr::FrameSetup);

        /// If offset is larger than 16 bits, build MOVK as well:
        if (OffsetQ2) {
            BuildMI(MBB, MBBI, dl, TII.get(FISC::MOVK), OffsetReg)
                .addReg(OffsetReg)
                .addImm(OffsetQ2)
                .setMIFlag(MachineInstr::FrameSetup);
        }

        /// If offset is larger than 32 bits, build another MOVK:
        if (OffsetQ3) {
            BuildMI(MBB, MBBI, dl, TII.get(FISC::MOVK), OffsetReg)
                .addReg(OffsetReg)
                .addImm(OffsetQ3)
                .setMIFlag(MachineInstr::FrameSetup);
        }

        /// If offset is larger than 48 bits, build a last MOVK:
        if (OffsetQ4) {
            BuildMI(MBB, MBBI, dl, TII.get(FISC::MOVK), OffsetReg)
                .addReg(OffsetReg)
                .addImm(OffsetQ4)
                .setMIFlag(MachineInstr::FrameSetup);
        }
        return OffsetReg;
    }
}

void FISCFrameLowering::emitPrologue(MachineFunction &MF, MachineBasicBlock &MBB) const {
    /// Compute the stack size, to determine if we need a prologue at all.
    const TargetInstrInfo &TII = *MF.getSubtarget().getInstrInfo();
    MachineBasicBlock::iterator MBBI = MBB.begin();
    DebugLoc dl = MBBI != MBB.end() ? MBBI->getDebugLoc() : DebugLoc();
    uint64_t StackSize = computeStackSize(MF);
    if (!StackSize)
        return;

    /// Adjust the stack pointer.
    unsigned StackReg  = FISC::SP;
    unsigned OffsetReg = materializeOffset(MF, MBB, MBBI, (unsigned)StackSize);
    if (OffsetReg) {
        BuildMI(MBB, MBBI, dl, TII.get(FISC::SUBrr), StackReg)
            .addReg(StackReg)
            .addReg(OffsetReg)
            .setMIFlag(MachineInstr::FrameSetup);
    } else {
        BuildMI(MBB, MBBI, dl, TII.get(FISC::SUBri), StackReg)
            .addReg(StackReg)
            .addImm(StackSize)
            .setMIFlag(MachineInstr::FrameSetup);
    }
}

void FISCFrameLowering::emitEpilogue(MachineFunction &MF, MachineBasicBlock &MBB) const {
    /// Compute the stack size, to determine if we need an epilogue at all.
    const TargetInstrInfo &TII = *MF.getSubtarget().getInstrInfo();
    MachineBasicBlock::iterator MBBI = MBB.getLastNonDebugInstr();
    DebugLoc dl = MBBI->getDebugLoc();
    uint64_t StackSize = computeStackSize(MF);
    if (!StackSize)
        return;

    /// Restore the stack pointer to what it was at the beginning of the function.
    unsigned StackReg  = FISC::SP;
    unsigned OffsetReg = materializeOffset(MF, MBB, MBBI, (unsigned)StackSize);
    if (OffsetReg) {
        BuildMI(MBB, MBBI, dl, TII.get(FISC::ADDrr), StackReg)
            .addReg(StackReg)
            .addReg(OffsetReg)
            .setMIFlag(MachineInstr::FrameSetup);
    } else {
        BuildMI(MBB, MBBI, dl, TII.get(FISC::ADDri), StackReg)
            .addReg(StackReg)
            .addImm(StackSize)
            .setMIFlag(MachineInstr::FrameSetup);
    }
}

/// This function eliminates ADJCALLSTACKDOWN, ADJCALLSTACKUP pseudo instructions
void FISCFrameLowering::eliminateCallFramePseudoInstr(MachineFunction &MF, MachineBasicBlock &MBB, 
                                                      MachineBasicBlock::iterator I) const 
{
    if (I->getOpcode() == FISC::ADJCALLSTACKUP || I->getOpcode() == FISC::ADJCALLSTACKDOWN)
        MBB.erase(I);
}
