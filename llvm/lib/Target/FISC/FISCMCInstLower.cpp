//===-- FISCMCInstLower.cpp - Convert FISC MachineInstr to MCInst -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains code to lower FISC MachineInstrs to their
// corresponding MCInst records.
//
//===----------------------------------------------------------------------===//
#include "FISCMCInstLower.h"
#include "MCTargetDesc/FISCBaseInfo.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/IR/Mangler.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"

using namespace llvm;

FISCMCInstLower::FISCMCInstLower(class AsmPrinter &asmprinter)
    : Printer(asmprinter) {}

void FISCMCInstLower::Initialize(Mangler *M, MCContext *C) {
    Mang = M;
    Ctx  = C;
}

MCOperand FISCMCInstLower::LowerSymbolOperand(const MachineOperand &MO,
                                              MachineOperandType MOTy,
                                              unsigned Offset) const 
{
    const MCSymbol *Symbol;
    
    switch (MOTy) {
    case MachineOperand::MO_MachineBasicBlock:
        Symbol = MO.getMBB()->getSymbol();
        break;
    case MachineOperand::MO_GlobalAddress:
        Symbol = Printer.getSymbol(MO.getGlobal());
        Offset += MO.getOffset();
        break;
    case MachineOperand::MO_BlockAddress:
        Symbol = Printer.GetBlockAddressSymbol(MO.getBlockAddress());
        Offset += MO.getOffset();
        break;
    case MachineOperand::MO_ExternalSymbol:
        Symbol = Printer.GetExternalSymbolSymbol(MO.getSymbolName());
        Offset += MO.getOffset();
        break;
    case MachineOperand::MO_JumpTableIndex:
        Symbol = Printer.GetJTISymbol(MO.getIndex());
        break;
    case MachineOperand::MO_ConstantPoolIndex:
        Symbol = Printer.GetCPISymbol(MO.getIndex());
        Offset += MO.getOffset();
        break;
    default:
        llvm_unreachable("<unknown operand type>");
    }

    const unsigned Option = MO.getTargetFlags() & FISCII::MO_OPTION_MASK;
    MCSymbolRefExpr::VariantKind Kind = MCSymbolRefExpr::VK_None;

    switch (Option) {
    default:
        break;
    case FISCII::MO_Q1:
        Kind = MCSymbolRefExpr::VK_FISC_Q1;
        break;
    case FISCII::MO_Q2:
        Kind = MCSymbolRefExpr::VK_FISC_Q2;
        break;
    case FISCII::MO_Q3:
        Kind = MCSymbolRefExpr::VK_FISC_Q3;
        break;
    case FISCII::MO_Q4:
        Kind = MCSymbolRefExpr::VK_FISC_Q4;
        break;
    case FISCII::MO_CALL26:
        Kind = MCSymbolRefExpr::VK_FISC_CALL26;
        break;
    case FISCII::MO_CALL19:
        Kind = MCSymbolRefExpr::VK_FISC_CALL19;
        break;
    case FISCII::MO_9BIT:
        Kind = MCSymbolRefExpr::VK_FISC_9BIT;
        break;
    case FISCII::MO_6BIT:
        Kind = MCSymbolRefExpr::VK_FISC_6BIT;
        break;
    case FISCII::MO_12BIT:
        Kind = MCSymbolRefExpr::VK_FISC_12BIT;
        break;
    case FISCII::MO_MOVRZ:
        Kind = MCSymbolRefExpr::VK_FISC_MOVRZ;
        break;
    }

    const MCSymbolRefExpr *MCSym = MCSymbolRefExpr::create(Symbol, Kind, *Ctx);
    
    if (!Offset)
        return MCOperand::createExpr(MCSym);

    /// Assume offset is never negative.
    assert(Offset > 0);

    const MCConstantExpr *OffsetExpr = MCConstantExpr::create(Offset, *Ctx);
    const MCBinaryExpr   *Add        = MCBinaryExpr::createAdd(MCSym, OffsetExpr, *Ctx);
    return MCOperand::createExpr(Add);
}

MCOperand FISCMCInstLower::LowerOperand(const MachineOperand &MO, unsigned offset) const {
    MachineOperandType MOTy = MO.getType();

    switch (MOTy) {
    default:
        llvm_unreachable("unknown operand type");
    case MachineOperand::MO_Register:
        /// Ignore all implicit register operands.
        if (MO.isImplicit())
            break;
        return MCOperand::createReg(MO.getReg());
    case MachineOperand::MO_Immediate:
        return MCOperand::createImm(MO.getImm() + offset);
    case MachineOperand::MO_MachineBasicBlock:
    case MachineOperand::MO_GlobalAddress:
    case MachineOperand::MO_ExternalSymbol:
    case MachineOperand::MO_JumpTableIndex:
    case MachineOperand::MO_ConstantPoolIndex:
    case MachineOperand::MO_BlockAddress:
        return LowerSymbolOperand(MO, MOTy, offset);
    case MachineOperand::MO_RegisterMask:
        break;
    }
    
    return MCOperand();
}

void FISCMCInstLower::Lower(const MachineInstr *MI, MCInst &OutMI) const {
    OutMI.setOpcode(MI->getOpcode());

    for (auto &MO : MI->operands()) {
        const MCOperand MCOp = LowerOperand(MO);

        if (MCOp.isValid())
            OutMI.addOperand(MCOp);
    }
}
