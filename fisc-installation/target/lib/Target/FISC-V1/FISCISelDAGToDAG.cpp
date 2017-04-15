//===-- FISCISelDAGToDAG.cpp - A dag to dag inst selector for FISC ------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines an instruction selector for the FISC target.
//
//===----------------------------------------------------------------------===//

#include "FISC.h"
#include "FISCTargetMachine.h"
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "FISCInstrInfo.h"

using namespace llvm;

/// FISCDAGToDAGISel - FISC specific code to select FISC machine
/// instructions for SelectionDAG operations.
namespace {
class FISCDAGToDAGISel : public SelectionDAGISel {
	const FISCSubtarget &Subtarget;

public:
	explicit FISCDAGToDAGISel(FISCTargetMachine &TM, CodeGenOpt::Level OptLevel)
		: SelectionDAGISel(TM, OptLevel), Subtarget(*TM.getSubtargetImpl()) {}

	SDNode *Select(SDNode *N) override;

	bool SelectAddr(SDValue Addr, SDValue &Base, SDValue &Offset);

	virtual const char *getPassName() const override {
		return "FISC DAG->DAG Pattern Instruction Selection";
	}

private:
	SDNode *SelectMoveImmediate(SDNode *N);
	SDNode *SelectConditionalBranch(SDNode *N);

// Include the pieces autogenerated from the target description.
#include "FISCGenDAGISel.inc"
};
} // end anonymous namespace

bool FISCDAGToDAGISel::SelectAddr(SDValue Addr, SDValue &Base, SDValue &Offset) {
	if (FrameIndexSDNode *FIN = dyn_cast<FrameIndexSDNode>(Addr)) {
		EVT PtrVT = getTargetLowering()->getPointerTy(CurDAG->getDataLayout());
		Base   = CurDAG->getTargetFrameIndex(FIN->getIndex(), PtrVT);
		Offset = CurDAG->getTargetConstant(0, Addr, MVT::i64);
		return true;
	}
	if (Addr.getOpcode() == ISD::TargetExternalSymbol ||
		Addr.getOpcode() == ISD::TargetGlobalAddress ||
		Addr.getOpcode() == ISD::TargetGlobalTLSAddress) 
	{
		return false; // direct calls.
	}

	Base = Addr;
	Offset = CurDAG->getTargetConstant(0, Addr, MVT::i64);
	return true;
}

SDNode *FISCDAGToDAGISel::SelectMoveImmediate(SDNode *N) {
	// Make sure the immediate size is supported.
	ConstantSDNode *ConstVal = cast<ConstantSDNode>(N);
	uint64_t ImmVal = ConstVal->getZExtValue();
	uint64_t SupportedMask = 0xfffffffff;
	if ((ImmVal & SupportedMask) != ImmVal)
		return SelectCode(N);

	// Select the low part of the immediate move.
	uint64_t LoMask = 0xffff;
	uint64_t HiMask = 0xffff0000;
	uint64_t ImmLo  = (ImmVal & LoMask);
	uint64_t ImmHi  = (ImmVal & HiMask);
	SDValue ConstLo = CurDAG->getTargetConstant(ImmLo, N, MVT::i64);
	MachineSDNode *Move =
	CurDAG->getMachineNode(FISC::MOVZ, N, MVT::i64, ConstLo);

	// Select the low part of the immediate move, if needed.
	if (ImmHi) {
		SDValue ConstHi = CurDAG->getTargetConstant(ImmHi >> 16, N, MVT::i64);
		Move = CurDAG->getMachineNode(FISC::MOVK, N, MVT::i64, SDValue(Move, 0), ConstHi);
	}

	return Move;
}

SDNode *FISCDAGToDAGISel::SelectConditionalBranch(SDNode *N) {
	SDValue Chain  = N->getOperand(0);
	SDValue Cond   = N->getOperand(1);
	SDValue LHS    = N->getOperand(2);
	SDValue RHS    = N->getOperand(3);
	SDValue Target = N->getOperand(4);
  
	// Generate a comparison instruction.
	EVT CompareTys[]     = { MVT::Other, MVT::Glue };
	SDVTList CompareVT   = CurDAG->getVTList(CompareTys);
	SDValue CompareOps[] = {LHS, RHS, Chain};
	SDNode *Compare      = CurDAG->getMachineNode(FISC::CMP, N, CompareVT, CompareOps);
  
	// Generate a predicated branch instruction.
	CondCodeSDNode *CC  = cast<CondCodeSDNode>(Cond.getNode());
	SDValue CCVal       = CurDAG->getTargetConstant(CC->get(), N, MVT::i64);
	SDValue BranchOps[] = {CCVal, Target, SDValue(Compare, 0), SDValue(Compare, 1)};
	return CurDAG->getMachineNode(FISC::Bcc, N, MVT::Other, BranchOps);
}

SDNode *FISCDAGToDAGISel::Select(SDNode *N) {
	switch (N->getOpcode()) {
	case ISD::Constant:
		return SelectMoveImmediate(N);
	case ISD::BR_CC:
		return SelectConditionalBranch(N);
	}

	return SelectCode(N);
}

/// createFISCISelDag - This pass converts a legalized DAG into a
/// FISC-specific DAG, ready for instruction scheduling.
///
FunctionPass *llvm::createFISCISelDag(FISCTargetMachine &TM, CodeGenOpt::Level OptLevel) {
	return new FISCDAGToDAGISel(TM, OptLevel);
}
