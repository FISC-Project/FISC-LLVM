//===-- FISCInstrFormats.td - FISC Instruction Formats ---*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Instruction format superclass
//===----------------------------------------------------------------------===//
class InstFISC<dag outs, dag ins, string asmstr, list<dag> pattern, InstrItinClass itin>
    : Instruction 
{
    field bits<32> Inst;

    let Namespace        = "FISC";
    let DecoderNamespace = "FISC";
    dag OutOperandList   = outs;
    dag InOperandList    = ins;
    let AsmString        = asmstr;
    let Pattern          = pattern;
    let Itinerary        = itin;
    let Size             = 4;
    field bits<32> SoftFail = 0;
}

// FISC pseudo instructions format
class FISCPseudoInst<dag outs, dag ins, string asmstr, list<dag> pattern>
    : InstFISC<outs, ins, asmstr, pattern, IIPseudo> 
{
    let isPseudo = 1;
}

class ALURInst<bits<11> opcode, dag outs, dag ins, string asmstr, list<dag> pattern>
    : InstFISC<outs, ins, asmstr, pattern, IIAlu> 
{
    let Inst{31-21} = opcode;
}

class ALUIInst<bits<10> opcode, dag outs, dag ins, string asmstr, list<dag> pattern>
    : InstFISC<outs, ins, asmstr, pattern, IIAlu> 
{
    let Inst{31-22} = opcode;
}

class IWInst<bits<9> opcode, dag outs, dag ins, string asmstr, list<dag> pattern>
    : InstFISC<outs, ins, asmstr, pattern, IIIW> 
{
    let Inst{31-23} = opcode;
}

class UncondBranchInst<bits<6> opcode, dag outs, dag ins, string asmstr, list<dag> pattern>
    : InstFISC<outs, ins, asmstr, pattern, IIBranch> 
{
    let Inst{31-26} = opcode;
}

class CondBranchInst<bits<8> opcode, dag outs, dag ins, string asmstr, list<dag> pattern>
    : InstFISC<outs, ins, asmstr, pattern, IIBranch> 
{
    let Inst{31-24} = opcode;
}