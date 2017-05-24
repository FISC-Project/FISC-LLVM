//===-- FISCInstPrinter.cpp - Convert FISC MCInst to assembly syntax ----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints a FISC MCInst to a .s file
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "fisc - asm-printer"

#include "FISC.h"
#include "FISCInstPrinter.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/CodeGen/ISDOpcodes.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <sstream>

using namespace llvm;

#include "FISCGenAsmWriter.inc"

static std::string FISC_ez_int2hex(int64_t val) {
    std::stringstream stream;
    stream << std::hex << val;
    return stream.str();
}

void FISCInstPrinter::printRegName(raw_ostream &OS, unsigned RegNo) const {
    OS << StringRef(getRegisterName(RegNo)).lower();
}

void FISCInstPrinter::printInst(const MCInst *MI, raw_ostream &O, StringRef Annot, const MCSubtargetInfo &STI) {
    printInstruction(MI, O);
    printAnnotation(O, Annot);
}

static void printExpr(const MCExpr *Expr, raw_ostream &OS) {
    int Offset = 0;
    const MCSymbolRefExpr *SRE;

    if (const MCBinaryExpr *BE = dyn_cast<MCBinaryExpr>(Expr)) {
        SRE = dyn_cast<MCSymbolRefExpr>(BE->getLHS());
        const MCConstantExpr *CE = dyn_cast<MCConstantExpr>(BE->getRHS());
        assert(SRE && CE && "Binary expression must be sym+const.");
        Offset = CE->getValue();
    } else {
        SRE = dyn_cast<MCSymbolRefExpr>(Expr);
        assert(SRE && "Unexpected MCExpr type.");
    }

    const MCSymbolRefExpr::VariantKind Kind = SRE->getKind();
    assert(Kind == MCSymbolRefExpr::VK_None    ||
           Kind == MCSymbolRefExpr::VK_FISC_Q1 ||
           Kind == MCSymbolRefExpr::VK_FISC_Q2 ||
           Kind == MCSymbolRefExpr::VK_FISC_Q3 || 
           Kind == MCSymbolRefExpr::VK_FISC_Q4 ||
           Kind == MCSymbolRefExpr::VK_FISC_CALL26 ||
           Kind == MCSymbolRefExpr::VK_FISC_CALL19 ||
           Kind == MCSymbolRefExpr::VK_FISC_9BIT);

    OS << SRE->getSymbol();

    if (Offset) {
        if (Offset > 0)
            OS << '+';
        OS << FISC_ez_int2hex(Offset);
    }
}

const char * FISC_condCodeToString(ISD::CondCode CC) {
    switch (CC) {
    default:
        llvm_unreachable("Invalid or unsupported condition code");
        return nullptr;
    case 1: // True if equal
        return "eq";
    case 5: // True if greater than
        return "gt";
    case 6: // True if greater than or equal
        return "ge";
    case 3: // True if less than
        return "lt";
    case 4: // True if less than or equal
        return "le";
    case 2: // True if not equal
        return "ne";
    }
}

/// Print a condition code (e.g. for predication).
void FISCInstPrinter::printCondCode(const MCInst *MI, unsigned OpNum, raw_ostream &O) {
    const MCOperand &Op = MI->getOperand(OpNum);
    ISD::CondCode CC = (ISD::CondCode)Op.getImm();
    const char *Str = FISC_condCodeToString(CC);
    O << Str;
}

/// Print a 'memsrc' operand which is a (Register, Offset) pair.
void FISCInstPrinter::printAddrModeMemSrc(const MCInst *MI, unsigned OpNum, raw_ostream &O) {
    const MCOperand &Op1 = MI->getOperand(OpNum);
    const MCOperand &Op2 = MI->getOperand(OpNum + 1);
    O << "[";
    printRegName(O, Op1.getReg());

    unsigned Offset = Op2.getImm();
    O << ", 0x" << FISC_ez_int2hex(Offset) << "]";
}

void FISCInstPrinter::printOperand(const MCInst *MI, unsigned OpNo, raw_ostream &O) {
    const MCOperand &Op = MI->getOperand(OpNo);
    if (Op.isReg()) {
        printRegName(O, Op.getReg());
        return;
    }

    if (Op.isImm()) {
        std::string lsl_str = "";

        if((MI->getOpcode() == FISC::MOVZ || MI->getOpcode() == FISC::MOVK || MI->getOpcode() == FISC::MOVRZ || MI->getOpcode() == FISC::MOVRK) && OpNo == 2)
            lsl_str = "lsl ";

        O << lsl_str << "0x" << FISC_ez_int2hex(Op.getImm());
        return;
    }

    assert(Op.isExpr() && "unknown operand kind in printOperand");
    printExpr(Op.getExpr(), O);
}
