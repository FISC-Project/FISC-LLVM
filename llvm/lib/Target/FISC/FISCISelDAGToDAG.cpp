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
#include "MCTargetDesc/FISCBaseInfo.h"
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "FISCInstrInfo.h"

#define DEBUG_TYPE "fisc - instruction selection"

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
    bool SelectAddr(SDValue Addr, SDValue &Base, SDValue &Offset); /// Called by FISCOperators.td @ ComplexPattern

    virtual const char *getPassName() const override {
        return "FISC DAG->DAG Pattern Instruction Selection";
    }

private:
    SDValue ConstantToRegisterExpand(SDNode * N, SDValue Constant);

    SDNode *SelectIndexedLoad(SDNode *N);
    SDNode *SelectIndexedStore(SDNode *N);
    SDNode *SelectFrameIndex(SDNode *N);
    SDNode *SelectTargetGlobalAddressforADD(SDNode * N, SDNode * N_TargetGlobAddr);
    SDNode *SelectConditionalBranch(SDNode *N);
    SDNode *SelectCompare(SDNode *N);
    SDNode *SelectCallFunctionPointer(SDNode *N);
    SDNode *SelectShifts(SDNode *N);
    SDNode *SelectMUL(SDNode *N);

    bool SelectInlineAsmMemoryOperand(const SDValue &Op,
                                      unsigned ConstraintID,
                                      std::vector<SDValue> &OutOps) override;

/// Include the pieces autogenerated from the target description.
#include "FISCGenDAGISel.inc"
};
} // end of anonymous namespace

SDValue FISCDAGToDAGISel::ConstantToRegisterExpand(SDNode * N, SDValue Constant) {
    /* This function deals with operands that are constants that should
    be replaced into a register output, where we'll load that constant into */

    /* We'll need to load this constant value into a new virtual register */

    /* Convert SDValue into uint64_t */
    uint64_t ImmVal = cast<ConstantSDNode>(Constant)->getZExtValue();
   
    /* Split the value into four 16 bits quadrants */
    uint64_t ImmQ1 = ImmVal  & 0xffff;
    uint64_t ImmQ2 = (ImmVal & 0xffff0000) >> 16;
    uint64_t ImmQ3 = (ImmVal & 0xffff00000000) >> 32;
    uint64_t ImmQ4 = (ImmVal & 0xffff000000000000) >> 48;

    /* Use MOVZ (LSL=0) to move the 1st quadrant (16 bits) into the register */
    SDValue SD_ImmQ1 = CurDAG->getTargetConstant(ImmQ1, N, MVT::i64);
    MachineSDNode * Move = CurDAG->getMachineNode(FISC::MOVZ, N, MVT::i64, SD_ImmQ1, CurDAG->getTargetConstant(0, N, MVT::i64));

    /* If the constant is bigger than 16 bits, we may need to use MOVK together with MOVZ */
    if (ImmQ2) {
        SDValue SD_ImmQ2 = CurDAG->getTargetConstant(ImmQ2, N, MVT::i64);
        Move = CurDAG->getMachineNode(FISC::MOVK, N, MVT::i64, SD_ImmQ2, CurDAG->getTargetConstant(1, N, MVT::i64), SDValue(Move, 0));
    }
    if (ImmQ3) {
        SDValue SD_ImmQ3 = CurDAG->getTargetConstant(ImmQ3, N, MVT::i64);
        Move = CurDAG->getMachineNode(FISC::MOVK, N, MVT::i64, SD_ImmQ3, CurDAG->getTargetConstant(2, N, MVT::i64), SDValue(Move, 0));
    }
    if (ImmQ4) {
        SDValue SD_ImmQ4 = CurDAG->getTargetConstant(ImmQ4, N, MVT::i64);
        Move = CurDAG->getMachineNode(FISC::MOVK, N, MVT::i64, SD_ImmQ4, CurDAG->getTargetConstant(3, N, MVT::i64), SDValue(Move, 0));
    }

    /* We're done converting this node */
    return SDValue(Move, 0);
}

bool FISCDAGToDAGISel::SelectAddr(SDValue Addr, SDValue &Base, SDValue &Offset) {
    if (FrameIndexSDNode *FIN = dyn_cast<FrameIndexSDNode>(Addr)) {
        EVT PtrVT = getTargetLowering()->getPointerTy(CurDAG->getDataLayout());
        Base      = CurDAG->getTargetFrameIndex(FIN->getIndex(), PtrVT);
        Offset    = CurDAG->getTargetConstant(0, Addr, MVT::i64);
        return true;
    }

    switch (Addr.getOpcode()) {
        case ISD::TargetExternalSymbol:
        case ISD::TargetGlobalAddress:
        case ISD::TargetGlobalTLSAddress:
            return false; /// direct calls.
    }
    
    Base   = Addr;
    Offset = CurDAG->getTargetConstant(0, Addr, MVT::i64);
    return true;
}

SDNode * FISCDAGToDAGISel::SelectIndexedLoad(SDNode *N) {
    LoadSDNode *LDNode = cast<LoadSDNode>(N);
    FrameIndexSDNode *FIN =	dyn_cast<FrameIndexSDNode>(N->getOperand(1));
    SDValue Base = LDNode->getBasePtr();
    SDValue Offset = CurDAG->getTargetConstant(0, LDNode, MVT::i64);
    unsigned Opc;

    switch (LDNode->getMemoryVT().getSimpleVT().SimpleTy) {
        case MVT::i8:
            Opc = FISC::LDRB;
            break;
        case MVT::i16: 
            Opc = FISC::LDRH;
            break;
        case MVT::i32:
            Opc = FISC::LDRSW;
            break;
        case MVT::i64:
            Opc = FISC::LDR;
            break;
        default:
            llvm_unreachable("Load operation does not support this data size!");
    }

    switch (Base.getOpcode()) {
    case ISD::TargetGlobalAddress: {
        GlobalAddressSDNode *GA = dyn_cast<GlobalAddressSDNode>(LDNode->getBasePtr());
        const GlobalValue   *GV = GA->getGlobal();
        unsigned char TargetFlags = FISCII::MO_MOVRZ;

        if (GV->getValueID() == Value::FunctionVal)
            TargetFlags = FISCII::MO_Q1;

        SDValue TargetGlobalAddr = CurDAG->getTargetGlobalAddress(GV, SDLoc(N), MVT::i64, GA->getOffset(), TargetFlags);
        MachineSDNode * Move = CurDAG->getMachineNode(FISC::MOVRZ, N, MVT::i64, TargetGlobalAddr, CurDAG->getTargetConstant(0, N, MVT::i64));
        Base = SDValue(Move, 0);
        break;
    }
    case ISD::FrameIndex:
        Base = CurDAG->getTargetFrameIndex(FIN->getIndex(), MVT::i64);
        break;
    case ISD::Constant:
        Base = ConstantToRegisterExpand(N, Base);
        break;
    case ISD::LOAD: /* Let LLVM select the default nodes for these */
    case ISD::CopyFromReg:
    case ISD::Register:
    case ISD::ADD:
    case ISD::AND:
    case ISD::OR:
    case FISCISD::LOAD_SYM: break;
   // default:
    //    DEBUG(errs() << ">> Opcode: " << Base.getOpcode() << "\n");
    //    llvm_unreachable("Unknown base pointer opcode!");
    }
   
    SDValue ops[]  = { Base, Offset, LDNode->getChain() };
    return CurDAG->getMachineNode(Opc, SDLoc(N), MVT::i64, MVT::Other, ops);
}

SDNode *FISCDAGToDAGISel::SelectIndexedStore(SDNode *N) {
    StoreSDNode *STNode = cast<StoreSDNode>(N);
    SDValue	Src = STNode->getValue();
    SDValue Base = STNode->getBasePtr();
    SDValue Offset = CurDAG->getTargetConstant(0, STNode, MVT::i64);
    unsigned Opc;
    
    switch (STNode->getMemoryVT().getSimpleVT().SimpleTy) {
    case MVT::i8:
        Opc = FISC::STRB;
        break;
    case MVT::i16:
        Opc = FISC::STRH;
        break;
    case MVT::i32:
        Opc = FISC::STRW;
        break;
    case MVT::i64:
        Opc = FISC::STR;
        break;
    default:
        llvm_unreachable("Load operation does not support this data size!");
    }

    /* Check for operands that need to be handled/converted */

    switch (Src.getOpcode()) {
    case ISD::Constant:
        /* Source operand is a constant. We must mutate it into a load into a virtual register  */
        Src = ConstantToRegisterExpand(N, Src);
        break;
    case ISD::TargetGlobalAddress: {
        GlobalAddressSDNode *GA = dyn_cast<GlobalAddressSDNode>(Src);
        const GlobalValue   *GV = GA->getGlobal();
        unsigned char TargetFlags = FISCII::MO_MOVRZ;

        if(GV->getValueID() == Value::FunctionVal)
            TargetFlags = FISCII::MO_Q1;

        SDValue TargetGlobalAddr = CurDAG->getTargetGlobalAddress(GV, SDLoc(N), MVT::i64, GA->getOffset(), TargetFlags);
        MachineSDNode * Move = CurDAG->getMachineNode(FISC::MOVRZ, N, MVT::i64, TargetGlobalAddr, CurDAG->getTargetConstant(0, N, MVT::i64));
        Src = SDValue(Move, 0);
        break;
    }
    default:
        /* Src is already set for this case */
        break;
    }

    switch (Base.getOpcode()) {
    case ISD::Constant: 
        /* Base register operand is a constant. We must mutate it into a load into a virtual register */
        Base = ConstantToRegisterExpand(N, Base);
        break;
    case ISD::CopyFromReg:
        /* Base register is a virtual/physical register. Base was already set to this. */
        break;
    case ISD::FrameIndex: {
        /* Fetch frame index from operand 2 from IR's STORE instruction */
        FrameIndexSDNode *FIN = dyn_cast<FrameIndexSDNode>(STNode->getBasePtr());
        Base = CurDAG->getTargetFrameIndex(FIN->getIndex(), MVT::i64);
        break;
    }
    case ISD::TargetGlobalAddress: {
        GlobalAddressSDNode *GA = dyn_cast<GlobalAddressSDNode>(Base);
        const GlobalValue   *GV = GA->getGlobal();
        unsigned char TargetFlags = FISCII::MO_MOVRZ;

        if (GV->getValueID() == Value::FunctionVal)
            TargetFlags = FISCII::MO_Q1;

        SDValue TargetGlobalAddr = CurDAG->getTargetGlobalAddress(GV, SDLoc(N), MVT::i64, GA->getOffset(), TargetFlags);
        MachineSDNode * Move = CurDAG->getMachineNode(FISC::MOVRZ, N, MVT::i64, TargetGlobalAddr, CurDAG->getTargetConstant(0, N, MVT::i64));
        Base = SDValue(Move, 0);
        break;
    }
    case ISD::LOAD: // Let LLVM select the default nodes for these
    case ISD::ADD:
    case ISD::AND:
    case ISD::OR:
    case ISD::Register: break;
   // default:
    //    DEBUG(errs() << ">> Opcode: " << Base.getOpcode() << "\n");
    //    llvm_unreachable("Unknown base pointer opcode!");
    }

    /* Build and return Store instruction with the following operands */	
    SDValue ops[] = { Src, Base, Offset, STNode->getChain() };
    return CurDAG->getMachineNode(Opc, SDLoc(N), MVT::Other, ops);
}

SDNode *FISCDAGToDAGISel::SelectFrameIndex(SDNode *N) {
    int FI = cast<FrameIndexSDNode>(N)->getIndex();
    SDValue TFI = CurDAG->getTargetFrameIndex(FI, TLI->getPointerTy(CurDAG->getDataLayout()));
    SDValue ops[] = { TFI, CurDAG->getTargetConstant(0, N, MVT::i64) };
    return CurDAG->SelectNodeTo(N, FISC::ADDri, MVT::i64, ops);
}

SDNode *FISCDAGToDAGISel::SelectTargetGlobalAddressforADD(SDNode * N, SDNode * N_TargetGlobAddr) {
    GlobalAddressSDNode *GA  = dyn_cast<GlobalAddressSDNode>(N_TargetGlobAddr);
    const GlobalValue   *GV  = GA->getGlobal();
    unsigned char TargetFlags = FISCII::MO_MOVRZ;

    if (GV->getValueID() == Value::FunctionVal)
        TargetFlags = FISCII::MO_Q1;

    SDValue TargetGlobalAddr = CurDAG->getTargetGlobalAddress(GV, SDLoc(N), MVT::i64, GA->getOffset(), TargetFlags);
    MachineSDNode * Move = CurDAG->getMachineNode(FISC::MOVRZ, N, MVT::i64, TargetGlobalAddr, CurDAG->getTargetConstant(0, N, MVT::i64));
    SDValue op2 = N->getOperand(1);
    unsigned Opcode;

    if (op2.getOpcode() == ISD::Constant) {
        op2 = CurDAG->getTargetConstant(cast<ConstantSDNode>(op2.getNode())->getZExtValue(), N, MVT::i64);
        Opcode = FISC::ADDri;
    }
    else {
        Opcode = FISC::ADDrr;
    }

    return CurDAG->getMachineNode(Opcode, SDLoc(N), MVT::i64, SDValue(Move, 0), op2);
}

SDNode *FISCDAGToDAGISel::SelectConditionalBranch(SDNode *N) {
    SDValue Chain  = N->getOperand(0);
    SDValue Cond   = N->getOperand(1);
    SDValue LHS    = N->getOperand(2);
    SDValue RHS    = N->getOperand(3);
    SDValue Target = N->getOperand(4);
 
    /// Generate a comparison instruction.
    EVT      CompareTys[] = { MVT::Other, MVT::Glue };
    SDVTList CompareVT    = CurDAG->getVTList(CompareTys);
    SDValue  CompareOps[] = {LHS, RHS, Chain};
    SDNode  *Compare      = CurDAG->getMachineNode(FISC::CMP, N, CompareVT, CompareOps);
  
    /// Generate a predicated branch instruction.
    CondCodeSDNode *CC = cast<CondCodeSDNode>(Cond.getNode());
    uint64_t TargetCCode;
    
    switch (CC->get()) {
    case ISD::CondCode::SETOEQ: case ISD::CondCode::SETUEQ: case ISD::CondCode::SETEQ: TargetCCode = FISC::COND_EQ; break;
    case ISD::CondCode::SETONE: case ISD::CondCode::SETUNE: case ISD::CondCode::SETNE: TargetCCode = FISC::COND_NE; break;
    case ISD::CondCode::SETOLT: case ISD::CondCode::SETULT: case ISD::CondCode::SETLT: TargetCCode = FISC::COND_LT; break;
    case ISD::CondCode::SETOLE: case ISD::CondCode::SETULE: case ISD::CondCode::SETLE: TargetCCode = FISC::COND_LE; break;
    case ISD::CondCode::SETOGT: case ISD::CondCode::SETUGT: case ISD::CondCode::SETGT: TargetCCode = FISC::COND_GT; break;
    case ISD::CondCode::SETOGE: case ISD::CondCode::SETUGE: case ISD::CondCode::SETGE: TargetCCode = FISC::COND_GE; break;
    default:
        llvm_unreachable("Condition code not supported!");
    }
       
    SDValue CCVal = CurDAG->getTargetConstant(TargetCCode, N, MVT::i64);
    SDValue BranchOps[] = {CCVal, Target, SDValue(Compare, 0), SDValue(Compare, 1)};
    return CurDAG->getMachineNode(FISC::Bcc, N, MVT::Other, BranchOps);
}

SDNode *FISCDAGToDAGISel::SelectCompare(SDNode *N) {
    SDValue LHS = N->getOperand(0);
    SDValue RHS = N->getOperand(1);

    SDValue  CompareOps[] = { LHS, RHS };
    return CurDAG->getMachineNode(FISC::CMP, N, MVT::Glue, CompareOps);
}

SDNode *FISCDAGToDAGISel::SelectCallFunctionPointer(SDNode *N)
{
    EVT BRLTys[] = { MVT::Other, MVT::Glue };
    unsigned int operand2Opc = N->getOperand(1).getOpcode();
    if(operand2Opc == ISD::LOAD) {
        return CurDAG->getMachineNode(FISC::BRL, N, BRLTys, { SDValue(SelectIndexedLoad(N->getOperand(1).getNode()), 0), N->getOperand(2), N->getOperand(0) });
    } else if(operand2Opc == ISD::CopyFromReg) {
        return CurDAG->getMachineNode(FISC::BRL, N, BRLTys, { N->getOperand(1), N->getOperand(2), N->getOperand(0) });
    }
    return SelectCode(N);
}

SDNode *FISCDAGToDAGISel::SelectShifts(SDNode *N)
{
    unsigned Opc = N->getOpcode();
    SDValue Src1 = N->getOperand(0);
    SDValue Src2 = N->getOperand(1);

    if (Src2.getOpcode() == ISD::LOAD)
        Src2 = SDValue(SelectIndexedLoad(Src2.getNode()), 0);

    if(Opc == ISD::SRL)
        return CurDAG->getMachineNode(FISC::LSR, N, MVT::i64, Src1, Src2);
    else if (Opc == ISD::SRA)
        return CurDAG->getMachineNode(FISC::LSR, N, MVT::i64, Src1, Src2);
    else if(Opc == ISD::SHL)
        return CurDAG->getMachineNode(FISC::LSL, N, MVT::i64, Src1, Src2);
    else
        return SelectCode(N);
}

SDNode *FISCDAGToDAGISel::SelectMUL(SDNode *N)
{
    SDValue Op1 = N->getOperand(0);
    SDValue Op2 = N->getOperand(1);
    return CurDAG->getMachineNode(FISC::MUL, N, MVT::i64, Op1, Op2);
}

SDNode *FISCDAGToDAGISel::Select(SDNode *N) {
    DEBUG(errs() << ">>>>>> Selecting Node: "; N->dump(CurDAG); errs() << "\n");

    switch (N->getOpcode()) {
    case ISD::LOAD:
        return SelectIndexedLoad(N);
    case ISD::STORE:
        return SelectIndexedStore(N);
    case ISD::FrameIndex:
        return SelectFrameIndex(N);
    case ISD::Constant:
        return ConstantToRegisterExpand(N, SDValue(N, 0)).getNode();
    case ISD::ADD:
        if (N->getOperand(0).getOpcode() == ISD::TargetGlobalAddress)
           return SelectTargetGlobalAddressforADD(N, N->getOperand(0).getNode()); // Simply replace this node with another ADDI or a set of MOVZ+MOVKs
        break;
    case FISCISD::CMP:
        return SelectCompare(N);
    case ISD::BR_CC:
        return SelectConditionalBranch(N);
    case ISD::CopyToReg:
        if (N->getOperand(2).getOpcode() == ISD::TargetGlobalAddress) {
            GlobalAddressSDNode *GA = dyn_cast<GlobalAddressSDNode>(N->getOperand(2));
            const GlobalValue   *GV = GA->getGlobal();
            unsigned char TargetFlags = FISCII::MO_MOVRZ;

            if (GV->getValueID() == Value::FunctionVal)
                TargetFlags = FISCII::MO_Q1;

            SDValue TargetGlobalAddr = CurDAG->getTargetGlobalAddress(GV, SDLoc(N), MVT::i64, GA->getOffset(), TargetFlags);
            MachineSDNode * Move = CurDAG->getMachineNode(FISC::MOVRZ, N, MVT::i64, TargetGlobalAddr, CurDAG->getTargetConstant(0, N, MVT::i64));
            
            /* Replace the last operand of CopyToReg from a 
               TargetGlobalAddress to a MOVRZ that moves the same 
               TargetGlobalAddress inside a register */
            CurDAG->ReplaceAllUsesWith(N->getOperand(2), SDValue(Move, 0));
        }
        break;
    case FISCISD::CALL: {
        unsigned int operand2Opc = N->getOperand(1).getOpcode();
        if (operand2Opc == ISD::LOAD || operand2Opc == ISD::CopyFromReg) {
            /* We are branching using a function pointer.
               We mustn't use the BL instruction in this case.
               We shall replace this CALL node with a BRL instruction (and we keep the load) */
            return SelectCallFunctionPointer(N);
        }
        break;
    }
    case ISD::SRL: // TODO: FIXME case ISD::SRA: case ISD::SHL:
        return SelectShifts(N);
    case ISD::MULHU: case ISD::MULHS:
        return SelectMUL(N);
    }

    return SelectCode(N);
}

bool FISCDAGToDAGISel::SelectInlineAsmMemoryOperand(const SDValue &Op, unsigned ConstraintID, std::vector<SDValue> &OutOps) {
    // All memory constraints can at least accept raw pointers.
    switch (ConstraintID) {
    default:
        llvm_unreachable("Unexpected asm memory constraint");
    case InlineAsm::Constraint_m:
        OutOps.push_back(Op);
        return false;
    }
    return true;
}

/// createFISCISelDag - This pass converts a legalized DAG into a
/// FISC-specific DAG, ready for instruction scheduling.
FunctionPass *llvm::createFISCISelDag(FISCTargetMachine &TM, CodeGenOpt::Level OptLevel) {
    return new FISCDAGToDAGISel(TM, OptLevel);
}
