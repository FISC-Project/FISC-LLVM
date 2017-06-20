//===-- FISCDelaySlotFiller.cpp - FISC Delay Slot Filler ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Simple pass to fill delay slots with useful instructions.
//
//===----------------------------------------------------------------------===//

#include "FISC.h"
#include "FISCInstrInfo.h"
#include "FISCTargetMachine.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/CodeGen/MachineBranchProbabilityInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetRegisterInfo.h"

using namespace llvm;

#define DEBUG_TYPE "fisc - delayslotfiller"

STATISTIC(FilledSlots, "Number of delay slots filled");

extern unsigned int FISCTextSectOffset;

namespace {
	typedef MachineBasicBlock::iterator Iter;
	typedef MachineBasicBlock::reverse_iterator ReverseIter;

	class Filler : public MachineFunctionPass {
	public:
		Filler(TargetMachine &tm)
			: MachineFunctionPass(ID) { }

		const char *getPassName() const override {
			return "FISC Delay Slot Filler";
		}

		bool runOnMachineFunction(MachineFunction &F) override {
			bool Changed = false;
			
			for (MachineFunction::iterator FI = F.begin(), FE = F.end(); FI != FE; ++FI)
			{
				Changed |= runOnMachineBasicBlock(*FI);
				FISCTextSectOffset += FI->size();
			}
			return Changed;
		}
	private:
		bool runOnMachineBasicBlock(MachineBasicBlock &MBB);

		static char ID;
	};
	char Filler::ID = 0;
} // end of anonymous namespace

static bool insertStall(MachineBasicBlock &MBB, Iter I, const FISCInstrInfo *TII, unsigned Opcode) {

#define INSERTBUBBLE() BuildMI(MBB, std::next(I), I->getDebugLoc(), TII->get(FISC::NOP))

	switch (Opcode) {
		case FISC::CMP:
			/* Insert 1 bubble on every CMP instruction */
			INSERTBUBBLE(); 
			return true;

		case FISC::MOVRZ: case FISC::MOVZ:
		case FISC::MOVRK: case FISC::MOVK: {
			/* Check if we have a MOVZMOVZ/RZ/K/RK after the current one */
			Iter INext = std::next(I);
			if(INext == MBB.end())
				return false;
			const MachineInstr *MI = &*INext;
			unsigned nextOpcode = MI->getOpcode();
			switch (nextOpcode) {
				case FISC::MOVRZ: case FISC::MOVZ:
				case FISC::MOVRK: case FISC::MOVK:
					return false;
			}
			/* Always insert 2 bubbles on the pipeline on every MOVZ/RZ/K/RK instruction */
			INSERTBUBBLE();
			INSERTBUBBLE();
			return true;
		}
	}

	return false;
}

/// runOnMachineBasicBlock - Fill in delay slots for the given basic block.
/// We assume there is only one delay slot per delayed instruction.
bool Filler::runOnMachineBasicBlock(MachineBasicBlock &MBB) {
	bool Changed = false;
	const FISCSubtarget &STI = MBB.getParent()->getSubtarget<FISCSubtarget>();
	const FISCInstrInfo *TII = STI.getInstrInfo();

	for (Iter I = MBB.begin(); I != MBB.end(); ++I) {
		const MachineInstr *MI = &*I;

		if (insertStall(MBB, I, TII, MI->getOpcode())) {
			FilledSlots++;
			Changed = true;
		}
	}

	return Changed;
}

/// createFISCDelaySlotFillerPass - Returns a pass that fills in delay
/// slots in FISC MachineFunctions
FunctionPass *llvm::createFISCDelaySlotFillerPass(FISCTargetMachine &tm) {
	return new Filler(tm);
}
