//===-- FISCInstrInfo.h - FISC Instruction Information --------*- C++ -*-===//
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

#ifndef FISCINSTRUCTIONINFO_H
#define FISCINSTRUCTIONINFO_H

#include "FISCRegisterInfo.h"
#include "llvm/Target/TargetInstrInfo.h"

#define GET_INSTRINFO_HEADER
#include "FISCGenInstrInfo.inc"

namespace llvm {

class FISCInstrInfo : public FISCGenInstrInfo {
    const FISCRegisterInfo RI;
    virtual void anchor();

public:
    FISCInstrInfo();

    /// getRegisterInfo - TargetInstrInfo is a superset of MRegister info.  As
    /// such, whenever a client has an instance of instruction info, it should
    /// always be able to get register info as well (through this method).
    ///
    const FISCRegisterInfo &getRegisterInfo() const { 
        return RI; 
    }

    /// isLoadFromStackSlot - If the specified machine instruction is a direct
    /// load from a stack slot, return the virtual or physical register number of
    /// the destination along with the FrameIndex of the loaded stack slot.  If
    /// not, return 0.  This predicate must return 0 if the instruction has
    /// any side effects other than loading from the stack slot.
    virtual unsigned isLoadFromStackSlot(const MachineInstr *MI, int &FrameIndex) const override;

    /// isStoreToStackSlot - If the specified machine instruction is a direct
    /// store to a stack slot, return the virtual or physical register number of
    /// the source reg along with the FrameIndex of the loaded stack slot.  If
    /// not, return 0.  This predicate must return 0 if the instruction has
    /// any side effects other than storing to the stack slot.
    virtual unsigned isStoreToStackSlot(const MachineInstr *MI, int &FrameIndex) const override;

    virtual bool AnalyzeBranch(MachineBasicBlock &MBB, MachineBasicBlock *&TBB,
                               MachineBasicBlock *&FBB,
                               SmallVectorImpl<MachineOperand> &Cond,
                               bool AllowModify) const override;

    virtual unsigned RemoveBranch(MachineBasicBlock &MBB) const override;
  
  
    virtual unsigned InsertBranch(MachineBasicBlock &MBB, MachineBasicBlock *TBB,
                                  MachineBasicBlock *FBB,
                                  ArrayRef<MachineOperand> Cond,
                                  DebugLoc DL) const override;

    virtual void copyPhysReg(MachineBasicBlock &MBB,
                             MachineBasicBlock::iterator I, DebugLoc DL,
                             unsigned DestReg, unsigned SrcReg,
                             bool KillSrc) const override;

    virtual void storeRegToStackSlot(MachineBasicBlock &MBB,
                                     MachineBasicBlock::iterator MI,
                                     unsigned SrcReg, bool isKill, int FrameIndex,
                                     const TargetRegisterClass *RC,
                                     const TargetRegisterInfo *TRI) const override;

    virtual void loadRegFromStackSlot(MachineBasicBlock &MBB,
                                      MachineBasicBlock::iterator MI,
                                      unsigned DestReg, int FrameIndex,
                                      const TargetRegisterClass *RC,
                                      const TargetRegisterInfo *TRI) const override;

    virtual bool expandPostRAPseudo(MachineBasicBlock::iterator MI) const override;
};
} // end namespace llvm

#endif
