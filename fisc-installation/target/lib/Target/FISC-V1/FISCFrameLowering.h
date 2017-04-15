//===-- FISCFrameLowering.h - Frame info for FISC Target ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef FISCFRAMEINFO_H
#define FISCFRAMEINFO_H

#include "llvm/Target/TargetFrameLowering.h"
#include "llvm/Target/TargetMachine.h"

namespace llvm {
class FISCSubtarget;

class FISCFrameLowering : public TargetFrameLowering {
public:
	FISCFrameLowering();

	/// emitProlog/emitEpilog - These methods insert prolog and epilog code into
	/// the function.
	void emitPrologue(MachineFunction &MF,
					MachineBasicBlock &MBB) const override;
	void emitEpilogue(MachineFunction &MF, MachineBasicBlock &MBB) const override;

	void eliminateCallFramePseudoInstr(MachineFunction &MF,
									   MachineBasicBlock &MBB,
									   MachineBasicBlock::iterator I) const override;

	bool hasFP(const MachineFunction &MF) const override;

	//! Stack slot size (8 bytes)
	static int stackSlotSize() { 
		return 8; 
	}

private:
	uint64_t computeStackSize(MachineFunction &MF) const;
};
}

#endif // FISCFRAMEINFO_H

