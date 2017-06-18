//===-- FISCAsmPrinter.cpp - FISC LLVM assembly writer ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains a printer that converts from our internal representation
// of machine-dependent LLVM code to the GAS-format FISC assembly language.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "fisc - asm-printer"

#include "FISC.h"
#include "InstPrinter/FISCInstPrinter.h"
#include "FISCInstrInfo.h"
#include "FISCMCInstLower.h"
#include "FISCSubtarget.h"
#include "FISCTargetMachine.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/MachineConstantPool.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetLoweringObjectFile.h"
#include <algorithm>
#include <cctype>

using namespace llvm;

namespace {
class FISCAsmPrinter : public AsmPrinter {
    FISCMCInstLower MCInstLowering;

public:
    explicit FISCAsmPrinter(TargetMachine &TM, std::unique_ptr<MCStreamer> Streamer)
        : AsmPrinter(TM, std::move(Streamer)), MCInstLowering(*this) {}

    virtual const char *getPassName() const {
        return "FISC Assembly Printer"; 
    }

    void EmitFunctionEntryLabel();
    void EmitInstruction(const MachineInstr *MI);
    void EmitFunctionBodyStart();

    bool PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                         unsigned AsmVariant, const char *ExtraCode,
                         raw_ostream &O) override;
    bool PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNum,
                               unsigned AsmVariant, const char *ExtraCode,
                               raw_ostream &O) override;
    void printOperand(const MachineInstr *MI, int opNum, raw_ostream &O);
};
} // end of anonymous namespace

void FISCAsmPrinter::EmitFunctionEntryLabel() {
    OutStreamer->EmitLabel(CurrentFnSym);
}

void FISCAsmPrinter::EmitInstruction(const MachineInstr *MI) {
    MCInst TmpInst;
    MCInstLowering.Lower(MI, TmpInst);
    EmitToStreamer(*OutStreamer, TmpInst);
}

void FISCAsmPrinter::EmitFunctionBodyStart() {
    MCInstLowering.Initialize(Mang, &MF->getContext());
}

bool FISCAsmPrinter::PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                                     unsigned AsmVariant, const char *ExtraCode,
                                     raw_ostream &O)
{
    // Does this asm operand have a single letter operand modifier?
    if (ExtraCode && ExtraCode[0]) {
        if (ExtraCode[1] != 0) return true; // Unknown modifier.

        const MachineOperand &MO = MI->getOperand(OpNo);
        switch (ExtraCode[0]) {
        default:
            // See if this is a generic print operand
            return AsmPrinter::PrintAsmOperand(MI, OpNo, AsmVariant, ExtraCode, O);
        case 'X': // hex const int
            if ((MO.getType()) != MachineOperand::MO_Immediate)
                return true;
            O << "0x" << StringRef(utohexstr(MO.getImm())).lower();
            return false;
        case 'x': // hex const int (low 16 bits)
            if ((MO.getType()) != MachineOperand::MO_Immediate)
                return true;
            O << "0x" << StringRef(utohexstr(MO.getImm() & 0xffff)).lower();
            return false;
        case 'd': // decimal const int
            if ((MO.getType()) != MachineOperand::MO_Immediate)
                return true;
            O << MO.getImm();
            return false;
        case 'm': // decimal const int minus 1
            if ((MO.getType()) != MachineOperand::MO_Immediate)
                return true;
            O << MO.getImm() - 1;
            return false;
        case 'z': {
            // $0 if zero, regular printing otherwise
            if (MO.getType() != MachineOperand::MO_Immediate)
                return true;
            int64_t Val = MO.getImm();
            if (Val)
                O << Val;
            else
                O << "xzr";
            return false;
        }
        }
    }

    printOperand(MI, OpNo, O);
    return false;
}

bool FISCAsmPrinter::PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNum,
                                           unsigned AsmVariant, const char *ExtraCode,
                                           raw_ostream &O)
{
    int Offset = 0;
    // Currently we are expecting either no ExtraCode or 'D'
    if (ExtraCode)
        return true; // Unknown modifier.

    const MachineOperand &MO = MI->getOperand(OpNum);
    assert(MO.isReg() && "unexpected inline asm memory operand");
    O << "[" << FISCInstPrinter::getRegisterName(MO.getReg()) << ", " << Offset << "]";

    return false;
}

void FISCAsmPrinter::printOperand(const MachineInstr *MI, int opNum, raw_ostream &O) {
    const MachineOperand &MO = MI->getOperand(opNum);
    bool closeP = false;

    if (MO.getTargetFlags())
        closeP = true;

    switch (MO.getTargetFlags()) {
    case MCSymbolRefExpr::VK_FISC_Q1: O << "%mov_q1("; break;
    case MCSymbolRefExpr::VK_FISC_Q2: O << "%mov_q2("; break;
    case MCSymbolRefExpr::VK_FISC_Q3: O << "%mov_q3("; break;
    case MCSymbolRefExpr::VK_FISC_Q4: O << "%mov_q4("; break;
    case MCSymbolRefExpr::VK_FISC_CALL26: O << "%call26("; break;
    case MCSymbolRefExpr::VK_FISC_CALL19: O << "%call19("; break;
    case MCSymbolRefExpr::VK_FISC_9BIT: O << "%ldst9("; break;
    case MCSymbolRefExpr::VK_FISC_6BIT: O << "%shmt6("; break;
    case MCSymbolRefExpr::VK_FISC_12BIT: O << "%imm12("; break;
    }

    switch (MO.getType()) {
    case MachineOperand::MO_Register:
        O << StringRef(FISCInstPrinter::getRegisterName(MO.getReg())).lower();
        break;

    case MachineOperand::MO_Immediate:
        O << MO.getImm();
        break;

    case MachineOperand::MO_MachineBasicBlock:
        O << *MO.getMBB()->getSymbol();
        return;

    case MachineOperand::MO_GlobalAddress:
        O << *getSymbol(MO.getGlobal());
        break;

    case MachineOperand::MO_BlockAddress: {
        MCSymbol *BA = GetBlockAddressSymbol(MO.getBlockAddress());
        O << BA->getName();
        break;
    }

    case MachineOperand::MO_ExternalSymbol:
        O << *GetExternalSymbolSymbol(MO.getSymbolName());
        break;

    case MachineOperand::MO_JumpTableIndex:
        O << MAI->getPrivateGlobalPrefix() << "JTI" << getFunctionNumber()
            << '_' << MO.getIndex();
        break;

    case MachineOperand::MO_ConstantPoolIndex:
        O << MAI->getPrivateGlobalPrefix() << "CPI"
            << getFunctionNumber() << "_" << MO.getIndex();
        if (MO.getOffset())
            O << "+" << MO.getOffset();
        break;

    default:
        llvm_unreachable("<unknown operand type>");
    }

    if (closeP) O << ")";
}

/// Force static initialization.
extern "C" void LLVMInitializeFISCAsmPrinter() {
    RegisterAsmPrinter<FISCAsmPrinter> X(TheFISCTarget);
}
