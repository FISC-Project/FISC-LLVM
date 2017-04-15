//===-- FISCISelLowering.h - FISC DAG Lowering Interface ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the interfaces that FISC uses to lower LLVM code into a
// selection DAG.
//
//===----------------------------------------------------------------------===//

#ifndef FISCISELLOWERING_H
#define FISCISELLOWERING_H

#include "FISC.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/Target/TargetLowering.h"

namespace llvm {

// Forward delcarations
class FISCSubtarget;
class FISCTargetMachine;

namespace FISCISD {
enum NodeType {
	// Start the numbering where the builtin ops and target ops leave off.
	FIRST_NUMBER = ISD::BUILTIN_OP_END,
	RET_FLAG,
	// This loads the symbol (e.g. global address) into a register.
	LOAD_SYM,
	// This loads a 64-bit immediate into a register.
	MOVEi64,
	CALL
};
}

//===--------------------------------------------------------------------===//
// TargetLowering Implementation
//===--------------------------------------------------------------------===//
class FISCTargetLowering : public TargetLowering {
public:
	explicit FISCTargetLowering(FISCTargetMachine &TM);

	/// LowerOperation - Provide custom lowering hooks for some operations.
	virtual SDValue LowerOperation(SDValue Op, SelectionDAG &DAG) const override;

	/// getTargetNodeName - This method returns the name of a target specific DAG node.
	virtual const char *getTargetNodeName(unsigned Opcode) const override;

private:
	const FISCSubtarget &Subtarget;

	SDValue LowerFormalArguments(SDValue Chain, CallingConv::ID CallConv,
								 bool isVarArg,
								 const SmallVectorImpl<ISD::InputArg> &Ins,
								 SDLoc dl, SelectionDAG &DAG,
								 SmallVectorImpl<SDValue> &InVals) const override;

	SDValue LowerCall(TargetLowering::CallLoweringInfo &CLI,
					  SmallVectorImpl<SDValue> &InVals) const override;

	SDValue LowerReturn(SDValue Chain, CallingConv::ID CallConv, bool isVarArg,
						const SmallVectorImpl<ISD::OutputArg> &Outs,
						const SmallVectorImpl<SDValue> &OutVals, SDLoc dl,
						SelectionDAG &DAG) const override;

	SDValue LowerCallResult(SDValue Chain, SDValue InGlue,
							CallingConv::ID CallConv, bool isVarArg,
							const SmallVectorImpl<ISD::InputArg> &Ins, SDLoc dl,
							SelectionDAG &DAG,
							SmallVectorImpl<SDValue> &InVals) const;

	bool CanLowerReturn(CallingConv::ID CallConv, MachineFunction &MF,
						bool isVarArg,
						const SmallVectorImpl<ISD::OutputArg> &ArgsFlags,
						LLVMContext &Context) const override;

	// LowerGlobalAddress - Emit a constant load to the global address.
	SDValue LowerGlobalAddress(SDValue Op, SelectionDAG &DAG) const;
};
}

#endif // FISCISELLOWERING_H

