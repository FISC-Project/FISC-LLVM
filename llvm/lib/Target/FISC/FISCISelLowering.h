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

// Forward declarations
class FISCSubtarget;
class FISCTargetMachine;

namespace FISCISD {
enum NodeType {
    /// Start the numbering where the builtin ops and target ops leave off.
    FIRST_NUMBER = ISD::BUILTIN_OP_END,
    RET_FLAG,
    /// This loads the symbol (e.g. global address) into a register.
    LOAD_SYM,
    /// This loads a 64-bit immediate into a register.
    MOVEi64,
    SELECT_CC,
    CALL,
    CMP
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

    MachineBasicBlock *EmitInstrWithCustomInserter(MachineInstr *MI, MachineBasicBlock *BB) const override;
    
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

    /// LowerGlobalAddress - Emit a constant load to the global address.
    SDValue LowerGlobalAddress(SDValue Op, SelectionDAG &DAG) const;

    /// LowerSelectCC - Lower a ternary if instruction
    SDValue LowerSelectCC(SDValue Op, SelectionDAG &DAG) const;

    // Inline asm support
    ConstraintType getConstraintType(StringRef Constraint) const override;

    /// Examine constraint string and operand type and determine a weight value.
    /// The operand object must already have been set up with the operand type.
    ConstraintWeight getSingleConstraintMatchWeight(
      AsmOperandInfo &info, const char *constraint) const override;

    /// This function parses registers that appear in inline-asm constraints.
    /// It returns pair (0, 0) on failure.
    std::pair<unsigned, const TargetRegisterClass *>
    parseRegForInlineAsmConstraint(const StringRef &C, MVT VT) const;

    std::pair<unsigned, const TargetRegisterClass *>
    getRegForInlineAsmConstraint(const TargetRegisterInfo *TRI,
                                 StringRef Constraint, MVT VT) const override;

    /// LowerAsmOperandForConstraint - Lower the specified operand into the Ops
    /// vector.  If it is invalid, don't add anything to Ops. If hasMemory is
    /// true it means one of the asm constraint of the inline asm instruction
    /// being processed is 'm'.
    void LowerAsmOperandForConstraint(SDValue Op,
                                      std::string &Constraint,
                                      std::vector<SDValue> &Ops,
                                      SelectionDAG &DAG) const override;

    bool isLegalAddressingMode(const DataLayout &DL, const AddrMode &AM,
                               Type *Ty, unsigned AS) const override;
};
} // end namespace llvm

#endif // FISCISELLOWERING_H

