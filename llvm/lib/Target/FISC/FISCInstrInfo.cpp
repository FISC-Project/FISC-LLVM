//===-- FISCInstrInfo.cpp - FISC Instruction Information ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the FISC implementation of the TargetInstrInfo class.
//
//===----------------------------------------------------------------------===//

#include "FISCInstrInfo.h"
#include "FISC.h"
#include "FISCMachineFunctionInfo.h"
#include "MCTargetDesc/FISCBaseInfo.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/MachineConstantPool.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/TargetRegistry.h"

#define GET_INSTRINFO_CTOR_DTOR
#include "FISCGenInstrInfo.inc"

using namespace llvm;

/// Pin the vtable to this file.
void FISCInstrInfo::anchor() {}

FISCInstrInfo::FISCInstrInfo()
  : FISCGenInstrInfo(FISC::ADJCALLSTACKDOWN, FISC::ADJCALLSTACKUP), RI() {}

/// isLoadFromStackSlot - If the specified machine instruction is a direct
/// load from a stack slot, return the virtual or physical register number of
/// the destination along with the FrameIndex of the loaded stack slot.  If
/// not, return 0.  This predicate must return 0 if the instruction has
/// any side effects other than loading from the stack slot.
unsigned FISCInstrInfo::isLoadFromStackSlot(const MachineInstr *MI, int &FrameIndex) const {
    assert(0 && "Unimplemented");
    return 0;
}
  
  /// isStoreToStackSlot - If the specified machine instruction is a direct
  /// store to a stack slot, return the virtual or physical register number of
  /// the source reg along with the FrameIndex of the loaded stack slot.  If
  /// not, return 0.  This predicate must return 0 if the instruction has
  /// any side effects other than storing to the stack slot.
unsigned FISCInstrInfo::isStoreToStackSlot(const MachineInstr *MI, int &FrameIndex) const {
    assert(0 && "Unimplemented");
    return 0;
}

//===----------------------------------------------------------------------===//
// Branch Analysis
//===----------------------------------------------------------------------===//
/// AnalyzeBranch - Analyze the branching code at the end of MBB, returning
/// true if it cannot be understood (e.g. it's a switch dispatch or isn't
/// implemented for a target).  Upon success, this returns false and returns
/// with the following information in various cases:
///
/// 1. If this block ends with no branches (it just falls through to its succ)
///    just return false, leaving TBB/FBB null.
/// 2. If this block ends with only an unconditional branch, it sets TBB to be
///    the destination block.
/// 3. If this block ends with an conditional branch and it falls through to
///    an successor block, it sets TBB to be the branch destination block and a
///    list of operands that evaluate the condition. These
///    operands can be passed to other TargetInstrInfo methods to create new
///    branches.
/// 4. If this block ends with an conditional branch and an unconditional
///    block, it returns the 'true' destination in TBB, the 'false' destination
///    in FBB, and a list of operands that evaluate the condition. These
///    operands can be passed to other TargetInstrInfo methods to create new
///    branches.
///
/// Note that RemoveBranch and InsertBranch must be implemented to support
/// cases where this method returns success.
///
bool FISCInstrInfo::AnalyzeBranch(MachineBasicBlock &MBB, MachineBasicBlock *&TBB,
                                  MachineBasicBlock *&FBB,
                                  SmallVectorImpl<MachineOperand> &Cond,
                                  bool AllowModify) const 
{
    bool HasCondBranch = false;
    TBB = nullptr;
    FBB = nullptr;
    for (MachineInstr &MI : MBB) {
        if (MI.getOpcode() == FISC::B) {
            MachineBasicBlock *TargetBB = MI.getOperand(0).getMBB();
            if (HasCondBranch)
                FBB = TargetBB;
            else
                TBB = TargetBB;
        } else if (MI.getOpcode() == FISC::Bcc) {
            MachineBasicBlock *TargetBB = MI.getOperand(1).getMBB();
            TBB = TargetBB;
            Cond.push_back(MI.getOperand(0));
            HasCondBranch = true;
        }
    }
    return false;
}

/// RemoveBranch - Remove the branching code at the end of the specific MBB.
/// This is only invoked in cases where AnalyzeBranch returns success. It
/// returns the number of instructions that were removed.
unsigned FISCInstrInfo::RemoveBranch(MachineBasicBlock &MBB) const {
    if (MBB.empty())
        return 0;
    unsigned NumRemoved = 0;
    auto I = MBB.end();
    do {
        --I;
        unsigned Opc = I->getOpcode();
        if ((Opc == FISC::B) || (Opc == FISC::Bcc)) {
            auto ToDelete = I;
            ++I;
            MBB.erase(ToDelete);
            NumRemoved++;
        }
    } while (I != MBB.begin());
    return NumRemoved;
}

/// InsertBranch - Insert branch code into the end of the specified
/// MachineBasicBlock.  The operands to this method are the same as those
/// returned by AnalyzeBranch.  This is only invoked in cases where
/// AnalyzeBranch returns success. It returns the number of instructions
/// inserted.
///
/// It is also invoked by tail merging to add unconditional branches in
/// cases where AnalyzeBranch doesn't apply because there was no original
/// branch to analyze.  At least this much must be implemented, else tail
/// merging needs to be disabled.
unsigned FISCInstrInfo::InsertBranch(MachineBasicBlock &MBB,
                                     MachineBasicBlock *TBB,
                                     MachineBasicBlock *FBB,
                                     ArrayRef<MachineOperand> Cond,
                                     DebugLoc DL) const 
{
    unsigned NumInserted = 0;
  
    /// Insert any conditional branch.
    if (Cond.size() > 0) {
        BuildMI(MBB, MBB.end(), DL, get(FISC::Bcc)).addOperand(Cond[0]).addMBB(TBB);
        NumInserted++;
    }
  
    /// Insert any unconditional branch.
    if (Cond.empty() || FBB) {
        BuildMI(MBB, MBB.end(), DL, get(FISC::B)).addMBB(Cond.empty() ? TBB : FBB);
        NumInserted++;
    }
    return NumInserted;
}

void FISCInstrInfo::copyPhysReg(MachineBasicBlock &MBB,
                                MachineBasicBlock::iterator I, DebugLoc DL,
                                unsigned DestReg, unsigned SrcReg,
                                bool KillSrc) const 
{
    BuildMI(MBB, I, I->getDebugLoc(), get(FISC::MOVrr), DestReg)
        .addReg(SrcReg, getKillRegState(KillSrc));
}

void FISCInstrInfo::storeRegToStackSlot(MachineBasicBlock &MBB,
                                        MachineBasicBlock::iterator I,
                                        unsigned SrcReg, bool isKill,
                                        int FrameIndex,
                                        const TargetRegisterClass *RC,
                                        const TargetRegisterInfo *TRI) const
{
    BuildMI(MBB, I, I->getDebugLoc(), get(FISC::STR))
        .addReg(SrcReg, getKillRegState(isKill))
        .addFrameIndex(FrameIndex).addImm(0);
}

void FISCInstrInfo::loadRegFromStackSlot(MachineBasicBlock &MBB,
                                         MachineBasicBlock::iterator I,
                                         unsigned DestReg, int FrameIndex,
                                         const TargetRegisterClass *RC,
                                         const TargetRegisterInfo *TRI) const
{
    BuildMI(MBB, I, I->getDebugLoc(), get(FISC::LDR), DestReg)
        .addFrameIndex(FrameIndex).addImm(0);
}

bool FISCInstrInfo::expandPostRAPseudo(MachineBasicBlock::iterator MI) const {
    switch (MI->getOpcode()) {
        default:
            return false;
        case FISC::MOVi64: {
            DebugLoc DL = MI->getDebugLoc();
            MachineBasicBlock &MBB = *MI->getParent();

            const unsigned DstReg = MI->getOperand(0).getReg();
            //TODO const MachineOperand & QuadrantImm = MI->getOperand(2);
            const bool DstIsDead  = MI->getOperand(0).isDead();

            const MachineOperand &MO = MI->getOperand(1);

            auto Q1 = BuildMI(MBB, MI, DL, get(FISC::MOVZ), DstReg);
            auto Q2 = BuildMI(MBB, MI, DL, get(FISC::MOVK))
                            .addReg(DstReg, RegState::Define | getDeadRegState(DstIsDead))
                            .addReg(DstReg);

            if (MO.isImm()) {
                const unsigned Imm = MO.getImm();
                const unsigned Lo16 = Imm & 0xffff;
                const unsigned Hi16 = (Imm >> 16) & 0xffff;
                Q1 = Q1.addImm(Lo16);
                Q2 = Q2.addImm(Hi16);
            } else {
                const GlobalValue *GV = MO.getGlobal();
                const unsigned TF = MO.getTargetFlags();
                Q1 = Q1.addGlobalAddress(GV, MO.getOffset(), TF | FISCII::MO_LO16);
                Q2 = Q2.addGlobalAddress(GV, MO.getOffset(), TF | FISCII::MO_HI16);
            }

            MBB.erase(MI);
            return true;
        }
    }
}
