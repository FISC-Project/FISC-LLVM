//===-- FISCOperators.td - FISC-specific operators ------*- tblgen-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Type profiles
//===----------------------------------------------------------------------===//

def MoveImm64Ty          : SDTypeProfile<1, 1, [SDTCisSameAs<0, 1>, SDTCisInt<0>]>;

def SDT_FISCCallSeqStart : SDCallSeqStart<[ SDTCisVT<0, i64> ]>;

def SDT_FISCCallSeqEnd   : SDCallSeqEnd<[SDTCisVT<0, i64>, SDTCisVT<1, i64>]>;

def FISCRetFlag          : SDNode<"FISCISD::RET_FLAG", SDTNone,
                           [SDNPHasChain, SDNPOptInGlue, SDNPVariadic]>;
def callseq_start        : SDNode<"ISD::CALLSEQ_START", SDT_FISCCallSeqStart,
                           [SDNPHasChain, SDNPOutGlue]>;
def callseq_end          : SDNode<"ISD::CALLSEQ_END",   SDT_FISCCallSeqEnd,
                           [SDNPHasChain, SDNPOptInGlue, SDNPOutGlue]>;

def SDT_FISCCall         : SDTypeProfile<0, -1, [SDTCisPtrTy<0>]>;

//===----------------------------------------------------------------------===//
// Custom SDNodes.
//===----------------------------------------------------------------------===//

def load_sym  : SDNode<"FISCISD::LOAD_SYM", SDTIntUnaryOp>;

def movei64   : SDNode<"FISCISD::MOVEi64", MoveImm64Ty>;

def fisc_call : SDNode<"FISCISD::CALL", SDT_FISCCall, [SDNPHasChain, SDNPOptInGlue, SDNPOutGlue, SDNPVariadic]>;

//===----------------------------------------------------------------------===//
// Operand Definitions.
//===----------------------------------------------------------------------===//

def b_target : Operand<OtherVT>;

def cc_val : Operand<i64> {
    let PrintMethod = "printCondCode";
}

def memsrc : Operand<i64> {
    let MIOperandInfo = (ops GRRegs, i64imm);
    let PrintMethod   = "printAddrModeMemSrc";
    let EncoderMethod = "getMemSrcValue";
}

def FISCimm26 : Operand<i64>, ImmLeaf<i64, [{
    // BR Address
    return Imm >= 0 && Imm < 67108864;
}]>;

def FISCimm19 : Operand<i64>, ImmLeaf<i64, [{
    // COND BR Address (CB)
    return Imm >= 0 && Imm < 524288;
}]>;

def FISCimm16 : Operand<i64>, ImmLeaf<i64, [{
    // MOV Immediate (IW)
    return Imm >= 0 && Imm < 65536;
}]>;

def FISCimm12 : Operand<i64>, ImmLeaf<i64, [{
    // ALU Immediate (I)
    return Imm >= 0 && Imm < 4096;
}]>;

def FISCimm9 : Operand<i64>, ImmLeaf<i64, [{
    // DT Address (D)
    return Imm >= 0 && Imm < 512;
}]>;

def FISCimm6 : Operand<i64>, ImmLeaf<i64, [{
    // shamt (R)
    return Imm >= 0 && Imm < 64;
}]>;

def FISCimm2 : Operand<i64>, ImmLeaf<i64, [{
    // MOVZ/K Quadrant (IW) / Op (D)
    return Imm >= 0 && Imm < 4;
}]>;

//===----------------------------------------------------------------------===//
// Complex Pattern Definitions.
//===----------------------------------------------------------------------===//

def addr : ComplexPattern<i64, 2, "SelectAddr", [], []>;
