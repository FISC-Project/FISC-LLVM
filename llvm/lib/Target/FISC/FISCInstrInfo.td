//===-- FISCInstrInfo.td - Target Description for FISC ---*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file describes the FISC instructions in TableGen format.
//
//===----------------------------------------------------------------------===//

include "FISCInstrFormats.td"
include "FISCOperators.td"

//===----------------------------------------------------------------------===//
// ALU Instructions
//===----------------------------------------------------------------------===//

multiclass BinOp<bits<11> opcode_r, bits<10> opcode_i, string opstr, SDNode opnode> 
{
    def rr : ALURInst<opcode_r, (outs GRRegs:$dst),
                                (ins GRRegs:$src1, GRRegs:$src2),
                                !strconcat(opstr, " $dst, $src1, $src2"),
                                [(set i64:$dst, (opnode i64:$src1, i64:$src2))]> 
    {
        bits<5> dst;
        bits<5> src1;
        bits<5> src2;
        let Inst{20-16} = src2;
        let Inst{15-10} = 0b000000; // shamt value is always 0 in this case
        let Inst{9-5}   = src1;
        let Inst{4-0}   = dst;
    }
    def ri : ALUIInst<opcode_i, (outs GRRegs:$dst),
                                (ins GRRegs:$src1, i64imm:$imm),
                                !strconcat(opstr, " $dst, $src1, $imm"),
                                [(set i64:$dst, (opnode i64:$src1, FISCimm12:$imm))]> 
    {
        bits<5>  dst;
        bits<5>  src1;
        bits<12> imm;
        let Inst{21-10} = imm;
        let Inst{9-5}   = src1;
        let Inst{4-0}   = dst;
    }
}

multiclass ShiftOp<bits<11> opcode, string opstr, SDNode opnode> 
{
    def : ALURInst<opcode, (outs GRRegs:$dst),
                           (ins GRRegs:$src1, i64imm:$imm),
                           !strconcat(opstr, " $dst, $src1, $imm"),
                           [(set i64:$dst, (opnode i64:$src1, FISCimm6:$imm))]> 
    {
        bits<5>  dst;
        bits<5>  src1;
        bits<6> imm;
        let Inst{20-16} = 31;
        let Inst{15-10} = imm;
        let Inst{9-5}   = src1;
        let Inst{4-0}   = dst;
    }
}

defm ADD  : BinOp<0b10001011000, 0b1001000100, "add",  add>;
defm ADDS : BinOp<0b10101011000, 0b1011000100, "adds", add>;
defm SUB  : BinOp<0b11001011000, 0b1101000100, "sub",  sub>;
defm SUBS : BinOp<0b10101011000, 0b1011000100, "subs", sub>;
defm AND  : BinOp<0b10001010000, 0b1001001000, "and",  and>;
defm ANDS : BinOp<0b11101010000, 0b1111001000, "ands", and>;
defm EOR  : BinOp<0b11001010000, 0b1101001000, "eor",  xor>;
defm ORR  : BinOp<0b10101010000, 0b1011001000, "orr",  or>;
defm LSL  : ShiftOp<0b11010011011, "lsl", shl>;
defm LSR  : ShiftOp<0b11010011010, "lsr", srl>;

//===----------------------------------------------------------------------===//
// Multiply Instructions
//===----------------------------------------------------------------------===//

def MUL  : ALURInst<0b10011011000, (outs GRRegs:$dst),
                   (ins GRRegs:$src1, GRRegs:$src2),
                   "mul $dst, $src1, $src2",
                   [(set i64:$dst, (mul i64:$src1, i64:$src2))]> 
{
    bits<5> dst;
    bits<5> src1;
    bits<5> src2;
    let Inst{20-16} = src2;
    let Inst{15-10} = 0b011111;
    let Inst{9-5}   = src1;
    let Inst{4-0}   = dst;
}

//===----------------------------------------------------------------------===//
// Mov Instructions
//===----------------------------------------------------------------------===//

def MOVrr  : ALUIInst<0b1001000100, (outs GRRegs:$dst), (ins GRRegs:$src),
                                    "mov $dst, $src",
                                    [/* No pattern */]> 
{
    bits<5> dst;
    bits<5> src;
    let Inst{21-10} = 0;
    let Inst{9-5}   = src;
    let Inst{4-0}   = dst;
}

//===----------------------------------------------------------------------===//
// Mov Immediate Instructions
//===----------------------------------------------------------------------===//

class MOV<bits<9> opcode, string opstr>
    : IWInst<opcode, (outs GRRegs:$dst), (ins i64imm:$imm, i64imm:$lsl),
            !strconcat(opstr, " $dst, $imm, $lsl"), []> 
{
    bits<5>  dst;
    bits<16> imm;
    bits<2>  lsl;
    let Inst{22-21} = lsl;
    let Inst{20-5}  = imm;
    let Inst{4-0}   = dst;
}

def MOVK : MOV<0b111100101, "movk">;
def MOVZ : MOV<0b110100101, "movz">;

def MOVi64 : InstFISC<(outs GRRegs:$dst), (ins i64imm:$src), "",
                     [(set i64:$dst, (movei64 imm:$src))]> 
{
    let isPseudo = 1;
}

//===----------------------------------------------------------------------===//
// Comparison Instructions
//===----------------------------------------------------------------------===//

def CMP : InstFISC<(outs), (ins GRRegs:$lhs, GRRegs:$rhs),
                    "cmp $lhs, $rhs", []> 
{
    bits<5> lhs;
    bits<5> rhs;
    let Inst{31-21} = 0b11101011000;
    let Inst{20-16} = rhs;
    let Inst{15-10} = 0;
    let Inst{9-5}   = lhs;
    let Inst{4-0}   = 31;
}

//===----------------------------------------------------------------------===//
// Load/Store Instructions
//===----------------------------------------------------------------------===//

def LDR  : InstFISC<(outs GRRegs:$val), (ins memsrc:$addr),
                   "ldr $val, $addr",
                   [(set i64:$val, (load addr:$addr))]> 
{
    bits<5>  val;
    bits<14> addr;
    let Inst{31-21} = 0b11111000010;
    let Inst{20-12} = addr{13-5};
    let Inst{11-10} = 0b00;
    let Inst{9-5}   = addr{4-0};
    let Inst{4-0}   = val;
}

def STR : InstFISC<(outs), (ins GRRegs:$val, memsrc:$addr),
                  "str $val, $addr",
                  [(store i64:$val, addr:$addr)]> 
{
    bits<17> addr;
    bits<5>  val;
    let Inst{31-21} = 0b11111000000;
    let Inst{20-12} = addr{13-5};
    let Inst{11-10} = 0b00;
    let Inst{9-5}   = addr{4-0};
    let Inst{4-0}   = val;
}

//===----------------------------------------------------------------------===//
// Return Instructions
//===----------------------------------------------------------------------===//

let isTerminator = 1, isReturn = 1, isBarrier = 1, Uses = [LR] in
{
    def RET : InstFISC<(outs), (ins variable_ops), "br lr",  [(FISCRetFlag)]> 
    {
        let Inst{31-0} = 0b11010110000111100000000000000000;
    }
}

//===----------------------------------------------------------------------===//
// Call Instructions
//===----------------------------------------------------------------------===//

let isCall = 1, Defs = [LR], Uses = [SP] in 
{
    def BL : UncondBranchInst<0b100101, (outs), (ins i64imm:$addr),
                              "bl $addr",
                              [(fisc_call imm:$addr)]>
    {
        bits<26> addr;
        let Inst{25-0} = addr;
    }
}

def : Pattern<(i64 (load_sym tglobaladdr:$addr)), [(MOVi64 $addr)]>;

//===----------------------------------------------------------------------===//
// Branch Instructions
//===----------------------------------------------------------------------===//

let isTerminator = 1, isBranch = 1, isBarrier = 1 in 
{
    def B : InstFISC<(outs), (ins b_target:$dst), "b $dst", [(br bb:$dst)]> 
    {
        bits<26> dst;
        let Inst{31-26} = 0b001010;
        let Inst{25-0}  = dst;
    }
}

let isTerminator = 1, isBranch = 1 in 
{
    def Bcc : InstFISC<(outs), (ins cc_val:$cc, b_target:$dst), "b$cc $dst",  []>;
}

//===----------------------------------------------------------------------===//
// Pseudo Instructions
//===----------------------------------------------------------------------===//

let Defs = [SP], Uses = [SP] in 
{
    def ADJCALLSTACKDOWN : FISCPseudoInst<(outs), (ins i64imm:$amt),
                                          "# ADJCALLSTACKDOWN $amt",
                                          [(callseq_start timm:$amt)]>;
    def ADJCALLSTACKUP   : FISCPseudoInst<(outs), (ins i64imm:$amt1, i64imm:$amt2),
                                          "# ADJCALLSTACKUP $amt1",
                                          [(callseq_end timm:$amt1, timm:$amt2)]>;
}
