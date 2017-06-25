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

multiclass BinOp<bits<11> opcode_r, bits<10> opcode_i, string opstr_r, string opstr_i, SDNode opnode> 
{
    def rr : ALURInst<opcode_r, (outs GRRegs:$dst),
                                (ins GRRegs:$src1, GRRegs:$src2),
                                !strconcat(opstr_r, " $dst, $src1, $src2"),
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
                                !strconcat(opstr_i, " $dst, $src1, $imm"),
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

class ShiftOp<bits<11> opcode, string opstr, SDNode opnode>
    : ALURInst<opcode, (outs GRRegs:$dst),
                       (ins GRRegs:$src1, i64imm:$imm),
                       !strconcat(opstr, " $dst, $src1, $imm"),
                       [(set i64:$dst, (opnode i64:$src1, FISCimm6:$imm))]> 
{
    bits<5>  dst;
    bits<5>  src1;
    bits<6>  imm;
    let Inst{20-16} = 31;
    let Inst{15-10} = imm;
    let Inst{9-5}   = src1;
    let Inst{4-0}   = dst;
}

defm ADD  : BinOp<0b10001011000, 0b1001000100, "add",  "addi",  add>;
defm ADDS : BinOp<0b10101011000, 0b1011000100, "adds", "addis", add>; // FIXME: There's a Node conflict between this add and the prev. line's add
defm SUB  : BinOp<0b11001011000, 0b1101000100, "sub",  "subi",  sub>;
defm SUBS : BinOp<0b10101011000, 0b1011000100, "subs", "subis", sub>; // FIXME: There's a Node conflict between this sub and the prev. line's sub
defm AND  : BinOp<0b10001010000, 0b1001001000, "and",  "andi",  and>;
defm ANDS : BinOp<0b11101010000, 0b1111001000, "ands", "andis", and>;
defm EOR  : BinOp<0b11001010000, 0b1101001000, "eor",  "eori",  xor>;
defm ORR  : BinOp<0b10101010000, 0b1011001000, "orr",  "orri",  or>;
def  LSL  : ShiftOp<0b11010011011, "lsl", shl>;
def  LSR  : ShiftOp<0b11010011010, "lsr", sra>;

//===----------------------------------------------------------------------===//
// No Operation
//===----------------------------------------------------------------------===//

def NOP : InstFISC<(outs), (ins), "nop", [], IIAlu>
{
    let Inst{31-21} = 0b10001011000;
    let Inst{20-16} = 31;
    let Inst{15-10} = 0;
    let Inst{9-5}   = 31;
    let Inst{4-0}   = 31;
}

//===----------------------------------------------------------------------===//
// Multiply Instructions
//===----------------------------------------------------------------------===//

def MUL : ALURInst<0b10011011000, (outs GRRegs:$dst),
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

def MOVrr : ALUIInst<0b1001000100, (outs GRRegs:$dst), (ins GRRegs:$src),
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

class MOV<bits<9> opcode, string opstr, dag ins>
    : IWInst<opcode, (outs GRRegs:$dst), ins,
            !strconcat(opstr, " $dst, $imm, $lsl"), []> 
{
    bits<5>  dst;
    bits<16> imm;
    bits<2>  lsl;
    let Inst{22-21} = lsl;
    let Inst{20-5}  = imm;
    let Inst{4-0}   = dst;
}

def MOVK  : MOV<0b111100101, "movk",(ins i64imm:$imm, i64imm:$lsl, i64imm:$ign)>;
def MOVZ  : MOV<0b110100101, "movz",(ins i64imm:$imm, i64imm:$lsl)>;
def MOVRK : MOV<0b111110101, "movrk",(ins i64imm:$imm, i64imm:$lsl, i64imm:$ign)>;
def MOVRZ : MOV<0b110110101, "movrz",(ins i64imm:$imm, i64imm:$lsl)>;

def MOVi64 : InstFISC<(outs GRRegs:$dst), (ins i64imm:$src), "",
                      [(set i64:$dst, (movei64 imm:$src))], IIPseudo> 
{
    let isPseudo      = 1;
    let isCodeGenOnly = 1;
}

//===----------------------------------------------------------------------===//
// Comparison Instructions
//===----------------------------------------------------------------------===//

def CMP : InstFISC<(outs), (ins GRRegs:$lhs, GRRegs:$rhs),
                    "cmp $lhs, $rhs", 
                    [(FISCCmp GRRegs:$lhs, GRRegs:$rhs)], IICmp> 
{
    bits<5> lhs;
    bits<5> rhs;
    let Inst{31-21} = 0b11101011000;
    let Inst{20-16} = rhs;
    let Inst{15-10} = 0;
    let Inst{9-5}   = lhs;
    let Inst{4-0}   = 31;

    let Defs = [CPSR];
}

def : Pat<(FISCCmp GRRegs:$lhs, GRRegs:$rhs),
          (SUBSrr GRRegs:$lhs, GRRegs:$rhs)>;

//===----------------------------------------------------------------------===//
// Load/Store Instructions
//===----------------------------------------------------------------------===//

class LOAD_TYPE<bits<11> opcode, bits<2> sz, string opstr> 
    : InstFISC<(outs GRRegs:$val), (ins memsrc:$addr),
               !strconcat(opstr, " $val, $addr"),
               [(set i64:$val, (load addr:$addr))], IILoad>
{
    bits<5>  val;
    bits<14> addr;
    let Inst{31-21}   = opcode;
    let Inst{20-12}   = addr{8-0};
    let Inst{11-10}   = sz;
    let Inst{9-5}     = addr{13-9};
    let Inst{4-0}     = val;
    let DecoderMethod = "DecodeMem";
}

class STORE_TYPE<bits<11> opcode, bits<2> sz, string opstr> 
    : InstFISC<(outs), (ins GRRegs:$val, memsrc:$addr),
               !strconcat(opstr, " $val, $addr"),
               [(store i64:$val, addr:$addr)], IIStore>
{
    bits<14> addr;
    bits<5>  val;
    let Inst{31-21}   = opcode;
    let Inst{20-12}   = addr{8-0};
    let Inst{11-10}   = sz;
    let Inst{9-5}     = addr{13-9};
    let Inst{4-0}     = val;
    let DecoderMethod = "DecodeMem";
}

def LDR    : LOAD_TYPE<0b11111000010, 0b00, "ldr">;                  
def LDRB   : LOAD_TYPE<0b00111000010, 0b01, "ldrb">;
def LDRH   : LOAD_TYPE<0b01111000010, 0b10, "ldrh">;
def LDRSW  : LOAD_TYPE<0b10111000100, 0b11, "ldrsw">;
def LDRXR  : LOAD_TYPE<0b11001000010, 0b00, "ldrxr">;

def LDRR   : LOAD_TYPE<0b11111010010, 0b00, "ldrr">;                  
def LDRBR  : LOAD_TYPE<0b00111010010, 0b01, "ldrbr">;
def LDRHR  : LOAD_TYPE<0b01111010010, 0b10, "ldrhr">;
def LDRSWR : LOAD_TYPE<0b10011000100, 0b11, "ldrswr">;
def LDRXRR : LOAD_TYPE<0b11001010010, 0b00, "ldrxrr">;


def STR    : STORE_TYPE<0b11111000000, 0b00, "str">;                  
def STRB   : STORE_TYPE<0b00111000000, 0b01, "strb">;
def STRH   : STORE_TYPE<0b01111000000, 0b10, "strh">;
def STRW   : STORE_TYPE<0b10111000000, 0b11, "strw">;
def STRXR  : STORE_TYPE<0b11001000000, 0b00, "strxr">;

def STRR   : STORE_TYPE<0b11111010000, 0b00, "strr">;                  
def STRBR  : STORE_TYPE<0b00111010000, 0b01, "strbr">;
def STRHR  : STORE_TYPE<0b01111010000, 0b10, "strhr">;
def STRWR  : STORE_TYPE<0b10111010000, 0b11, "strwr">;
def STRXRR : STORE_TYPE<0b10111010001, 0b00, "strxrr">;

//===----------------------------------------------------------------------===//
// Return Instructions
//===----------------------------------------------------------------------===//

let isTerminator = 1, isReturn = 1, Uses = [LR] in
{
    def RET : InstFISC<(outs), (ins variable_ops), "br lr",  [(FISCRetFlag)], IIBranch> 
    {
        let Inst{31-0} = 0b11010110000000000000000000011110;
    }
}

def LDPC : InstFISC<(outs), (ins), "ldpc", [], IIAlu>
{
    let Inst{31-0} = 0b10101000100000000000000000000000;
}

//===----------------------------------------------------------------------===//
// Call Instructions
//===----------------------------------------------------------------------===//

let isCall = 1, Defs = [LR], Uses = [SP] in 
{
    def BL : UncondBranchInst<0b100101, (outs), (ins calltarget:$addr), "bl $addr", []>
    {
        bits<26> addr;
        let Inst{25-0} = addr;
        let DecoderMethod = "DecodeJumpTarget";
    }
}

def : Pat<(fisc_call i64:$dst), (BL tglobaladdr:$dst)>;
def : Pattern<(i64 (load_sym tglobaladdr:$addr)), [(MOVi64 tglobaladdr:$addr)]>;

//===----------------------------------------------------------------------===//
// Branch Instructions
//===----------------------------------------------------------------------===//

let isTerminator = 1, isBranch = 1, isBarrier = 1 in
{
    def B : InstFISC<(outs), (ins b_target:$dst), "b $dst", [(br bb:$dst)], IIBranch>
    {
        bits<26> dst;
        let Inst{31-26} = 0b001010;
        let Inst{25-0}  = dst;
    }
}

let isCall = 1, Defs = [LR], Uses = [SP] in
{
    def BRL : InstFISC<(outs), (ins GRRegs:$dst), "brl $dst", [(brind GRRegs:$dst)], IIBranch>
    {
        bits<5> dst;
        let Inst{31-21} = 0b11010110001;
        let Inst{4-0}  = dst;
    }
}

let isTerminator = 1, isBranch = 1, Uses = [CPSR] in 
{
    def Bcc : InstFISC<(outs), (ins cc_val:$cc, bcc_target:$dst), "b$cc $dst",  [], IIBranch> 
    {
        bits<19> dst;
        bits<5>  cc;
        let Inst{31-24} = 0b01010100;
        let Inst{23-5}  = dst;
        let Inst{4-0}   = cc;
    }
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

let usesCustomInserter = 1 in {
    def Select : FISCPseudoInst<(outs GRRegs:$dst),
                                (ins GRRegs:$lhs, GRRegs:$rhs, i64imm:$cc),
                                "# Select PSEUDO",
                                [(set i64:$dst,
                                 (FISCSelectCC i64:$lhs, i64:$rhs, imm:$cc))]>;
}
