//===-- FISCISelLowering.cpp - FISC DAG Lowering Implementation ---------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the FISCTargetLowering class.
//
//===----------------------------------------------------------------------===//

#include "FISCISelLowering.h"
#include "FISC.h"
#include "FISCMachineFunctionInfo.h"
#include "FISCSubtarget.h"
#include "FISCTargetMachine.h"
#include "MCTargetDesc/FISCBaseInfo.h"
#include "llvm/CodeGen/CallingConvLower.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/CodeGen/TargetLoweringObjectFileImpl.h"
#include "llvm/CodeGen/ValueTypes.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

const char *FISCTargetLowering::getTargetNodeName(unsigned Opcode) const {
    switch (Opcode) {
    default:
        return NULL;
    case FISCISD::RET_FLAG: return "RetFlag";
    case FISCISD::LOAD_SYM: return "LOAD_SYM";
    case FISCISD::MOVEi64:  return "MOVEi64";
    case FISCISD::CALL:     return "CALL";
    }
}

FISCTargetLowering::FISCTargetLowering(FISCTargetMachine &FISCTM)
    : TargetLowering(FISCTM), Subtarget(*FISCTM.getSubtargetImpl())
{
    /// Set up the register classes.
    addRegisterClass(MVT::i64, &FISC::GRRegsRegClass);

    /// Compute derived properties from the register classes
    computeRegisterProperties(Subtarget.getRegisterInfo());

    setStackPointerRegisterToSaveRestore(FISC::SP);

    setSchedulingPreference(Sched::Source);

    /// Nodes that require custom lowering
    setOperationAction(ISD::GlobalAddress, MVT::i64, Custom);
}

SDValue FISCTargetLowering::LowerOperation(SDValue Op, SelectionDAG &DAG) const {
    switch (Op.getOpcode()) {
    default:
        llvm_unreachable("Unimplemented operand");
    case ISD::GlobalAddress:
        return LowerGlobalAddress(Op, DAG);
    }
}

SDValue FISCTargetLowering::LowerGlobalAddress(SDValue Op, SelectionDAG& DAG) const {
    EVT VT = Op.getValueType();
    GlobalAddressSDNode *GlobalAddr = cast<GlobalAddressSDNode>(Op.getNode());
    SDValue TargetAddr = DAG.getTargetGlobalAddress(GlobalAddr->getGlobal(), Op, MVT::i64, 0, FISCII::MO_CALL26);
    return TargetAddr;
}

//===----------------------------------------------------------------------===//
//                      Calling Convention Implementation
//===----------------------------------------------------------------------===//

#include "FISCGenCallingConv.inc"

//===----------------------------------------------------------------------===//
//                  Call Calling Convention Implementation
//===----------------------------------------------------------------------===//

/// FISC call implementation
SDValue FISCTargetLowering::LowerCall(TargetLowering::CallLoweringInfo &CLI, SmallVectorImpl<SDValue> &InVals) const {
    /// Fetch data from the CallLoweringInfo class
    SelectionDAG &DAG                     = CLI.DAG;
    SDLoc &Loc                            = CLI.DL;
    SmallVectorImpl<ISD::OutputArg> &Outs = CLI.Outs;
    SmallVectorImpl<SDValue> &OutVals     = CLI.OutVals;
    SmallVectorImpl<ISD::InputArg> &Ins   = CLI.Ins;
    SDValue Chain                         = CLI.Chain;
    SDValue Callee                        = CLI.Callee;
    CallingConv::ID CallConv              = CLI.CallConv;
    const bool isVarArg                   = CLI.IsVarArg;

    CLI.IsTailCall = false;

    if (isVarArg) {
        llvm_unreachable("Unimplemented");
    }

    /// Analyze operands of the call, assigning locations to each operand.
    SmallVector<CCValAssign, 16> ArgLocs;
    CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), ArgLocs, *DAG.getContext());
    CCInfo.AnalyzeCallOperands(Outs, CC_FISC);

    /// Get the size of the outgoing arguments stack space requirement.
    const unsigned NumBytes = CCInfo.getNextStackOffset();

    Chain = DAG.getCALLSEQ_START(Chain, DAG.getIntPtrConstant(NumBytes, Loc, true), Loc);

    SmallVector<std::pair<unsigned, SDValue>, 8> RegsToPass;
    SmallVector<SDValue, 8>                      MemOpChains;

    /// Walk the register/memloc assignments, inserting copies/loads.
    for (unsigned i = 0, e = ArgLocs.size(); i != e; ++i) {
        CCValAssign &VA = ArgLocs[i];
        SDValue Arg     = OutVals[i];

        // We only handle fully promoted arguments.
        assert(VA.getLocInfo() == CCValAssign::Full && "Unhandled loc info");

        if (VA.isRegLoc()) {
            RegsToPass.push_back(std::make_pair(VA.getLocReg(), Arg));
            continue;
        }

        assert(VA.isMemLoc() && "Only support passing arguments through registers or via the stack");

        SDValue StackPtr = DAG.getRegister(FISC::SP, MVT::i64);
        SDValue PtrOff   = DAG.getIntPtrConstant(VA.getLocMemOffset(), Loc);
        PtrOff = DAG.getNode(ISD::ADD, Loc, MVT::i64, StackPtr, PtrOff);
        MemOpChains.push_back(DAG.getStore(Chain, Loc, Arg, PtrOff, MachinePointerInfo(), false, false, 0));
    }

    /// Emit all stores, make sure they occur before the call.
    if (!MemOpChains.empty())
        Chain = DAG.getNode(ISD::TokenFactor, Loc, MVT::Other, MemOpChains);

    /// Build a sequence of copy-to-reg nodes chained together with token chain
    /// and flag operands which copy the outgoing args into the appropriate regs.
    SDValue InFlag;
    for (auto &Reg : RegsToPass) {
        Chain  = DAG.getCopyToReg(Chain, Loc, Reg.first, Reg.second, InFlag);
        InFlag = Chain.getValue(1);
    }

    /// We only support calling global addresses.
    GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee);
    assert(G && "We only support the calling of global addresses");

    EVT PtrVT = getPointerTy(DAG.getDataLayout());
    Callee    = DAG.getGlobalAddress(G->getGlobal(), Loc, PtrVT, 0);

    std::vector<SDValue> Ops;
    Ops.push_back(Chain);
    Ops.push_back(Callee);

    /// Add argument registers to the end of the list so that they are known live into the call.
    for (auto &Reg : RegsToPass)
        Ops.push_back(DAG.getRegister(Reg.first, Reg.second.getValueType()));

    /// Add a register mask operand representing the call-preserved registers.
    const uint32_t *Mask;
    const TargetRegisterInfo *TRI = DAG.getSubtarget().getRegisterInfo();
    Mask = TRI->getCallPreservedMask(DAG.getMachineFunction(), CallConv);

    assert(Mask && "Missing call preserved mask for calling convention");
    Ops.push_back(DAG.getRegisterMask(Mask));

    if (InFlag.getNode())
        Ops.push_back(InFlag);
    
    SDVTList NodeTys = DAG.getVTList(MVT::Other, MVT::Glue);

    /// Returns a chain and a flag for retval copy to use.
    Chain  = DAG.getNode(FISCISD::CALL, Loc, NodeTys, Ops);
    InFlag = Chain.getValue(1);
    Chain  = DAG.getCALLSEQ_END(Chain, DAG.getIntPtrConstant(NumBytes, Loc, true),
                                DAG.getIntPtrConstant(0, Loc, true), InFlag, Loc);
    if (!Ins.empty())
        InFlag = Chain.getValue(1);

    /// Handle result values, copying them out of physregs into vregs that we return.
    return LowerCallResult(Chain, InFlag, CallConv, isVarArg, Ins, Loc, DAG, InVals);
}

SDValue FISCTargetLowering::LowerCallResult(
    SDValue Chain, SDValue InGlue, CallingConv::ID CallConv, bool isVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, SDLoc dl, SelectionDAG &DAG,
    SmallVectorImpl<SDValue> &InVals) const 
{
    assert(!isVarArg && "Unsupported");

    /// Assign locations to each value returned by this call.
    SmallVector<CCValAssign, 16> RVLocs;
    CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), RVLocs, *DAG.getContext());

    CCInfo.AnalyzeCallResult(Ins, RetCC_FISC);

    /// Copy all of the result registers out of their specified physreg.
    for (auto &Loc : RVLocs) {
        Chain  = DAG.getCopyFromReg(Chain, dl, Loc.getLocReg(), Loc.getValVT(), InGlue).getValue(1);
        InGlue = Chain.getValue(2);
        InVals.push_back(Chain.getValue(0));
    }

    return Chain;
}

//===----------------------------------------------------------------------===//
//             Formal Arguments Calling Convention Implementation
//===----------------------------------------------------------------------===//

/// FISC formal arguments implementation
SDValue FISCTargetLowering::LowerFormalArguments(
    SDValue Chain, CallingConv::ID CallConv, bool isVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, SDLoc dl, SelectionDAG &DAG,
    SmallVectorImpl<SDValue> &InVals) const 
{
    MachineFunction     &MF      = DAG.getMachineFunction();
    MachineRegisterInfo &RegInfo = MF.getRegInfo();

    assert(!isVarArg && "VarArg not supported");

    /// Assign locations to all of the incoming arguments.
    SmallVector<CCValAssign, 16> ArgLocs;
    CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), ArgLocs, *DAG.getContext());

    CCInfo.AnalyzeFormalArguments(Ins, CC_FISC);

    for (auto &VA : ArgLocs) {
        if (VA.isRegLoc()) {
            /// Arguments passed in registers
            EVT RegVT = VA.getLocVT();
            assert(RegVT.getSimpleVT().SimpleTy == MVT::i64 &&
                    "Only support MVT::i64 register passing");
            const unsigned VReg = RegInfo.createVirtualRegister(&FISC::GRRegsRegClass);
            RegInfo.addLiveIn(VA.getLocReg(), VReg);
            SDValue ArgIn = DAG.getCopyFromReg(Chain, dl, VReg, RegVT);

            InVals.push_back(ArgIn);
            continue;
        }

        assert(VA.isMemLoc() && "Can only pass arguments as either registers or via the stack");

        const unsigned Offset = VA.getLocMemOffset();

        const int FI = MF.getFrameInfo()->CreateFixedObject(8, Offset, true);
        EVT PtrTy = getPointerTy(DAG.getDataLayout());
        SDValue FIPtr = DAG.getFrameIndex(FI, PtrTy);

        assert(VA.getValVT() == MVT::i64 && "Only support passing arguments as i64");

        SDValue Load = DAG.getLoad(VA.getValVT(), dl, Chain, FIPtr, MachinePointerInfo(), false, false, false, 0);
        InVals.push_back(Load);
    }

  return Chain;
}

//===----------------------------------------------------------------------===//
//               Return Value Calling Convention Implementation
//===----------------------------------------------------------------------===//

bool FISCTargetLowering::CanLowerReturn(CallingConv::ID CallConv, 
                                        MachineFunction &MF, bool isVarArg,
                                        const SmallVectorImpl<ISD::OutputArg> &Outs,
                                        LLVMContext &Context) const 
{
    SmallVector<CCValAssign, 16> RVLocs;
    CCState CCInfo(CallConv, isVarArg, MF, RVLocs, Context);
    if (!CCInfo.CheckReturn(Outs, RetCC_FISC))
        return false;
    if (CCInfo.getNextStackOffset() != 0 && isVarArg)
        return false;
    return true;
}

SDValue FISCTargetLowering::LowerReturn(SDValue Chain, CallingConv::ID CallConv,
                                        bool isVarArg,
                                        const SmallVectorImpl<ISD::OutputArg> &Outs,
                                        const SmallVectorImpl<SDValue> &OutVals,
                                        SDLoc dl, SelectionDAG &DAG) const
{
    if (isVarArg)
        report_fatal_error("VarArg not supported");

    /// CCValAssign - represent the assignment of the return value to a location
    SmallVector<CCValAssign, 16> RVLocs;

    /// CCState - Info about the registers and stack slot.
    CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), RVLocs, *DAG.getContext());
    CCInfo.AnalyzeReturn(Outs, RetCC_FISC);

    SDValue Flag;
    SmallVector<SDValue, 8> RetOps(1, Chain);

    /// Copy the result values into the output registers.
    for (unsigned i = 0, e = RVLocs.size(); i < e; ++i) {
        CCValAssign &VA = RVLocs[i];
        assert(VA.isRegLoc() && "Can only return in registers!");

        Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(), OutVals[i], Flag);
        Flag  = Chain.getValue(1);
        RetOps.push_back(DAG.getRegister(VA.getLocReg(), VA.getLocVT()));
    }

    /// Update chain.
    RetOps[0] = Chain;

    /// Add the flag if we have it.
    if (Flag.getNode())
        RetOps.push_back(Flag);

    return DAG.getNode(FISCISD::RET_FLAG, dl, MVT::Other, RetOps);
}
