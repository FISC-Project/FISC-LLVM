//===-- FISC/FISCMCCodeEmitter.cpp - Convert FISC code to machine code -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the FISCMCCodeEmitter class.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "fisc - mc code emitter"

#include "MCTargetDesc/FISCMCTargetDesc.h"
#include "MCTargetDesc/FISCFixupKinds.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

STATISTIC(MCNumEmitted, "Number of MC instructions emitted.");

namespace {
class FISCMCCodeEmitter : public MCCodeEmitter {
    FISCMCCodeEmitter(const FISCMCCodeEmitter &) = delete;
    void operator=(const FISCMCCodeEmitter &) = delete;
    const MCInstrInfo &MCII;
    const MCContext   &CTX;

public:
    FISCMCCodeEmitter(const MCInstrInfo &mcii, MCContext &ctx)
        : MCII(mcii), CTX(ctx) {}

    ~FISCMCCodeEmitter() {}

    /// getBinaryCodeForInstr - TableGen'erated function for getting the
    /// binary encoding for an instruction.
    uint64_t getBinaryCodeForInstr(const MCInst &MI,
                                   SmallVectorImpl<MCFixup> &Fixups,
                                   const MCSubtargetInfo &STI) const;

    /// getMachineOpValue - Return binary encoding of operand. If the machine
    /// operand requires relocation, record the relocation and return zero.
    unsigned getMachineOpValue(const MCInst &MI, const MCOperand &MO,
                               SmallVectorImpl<MCFixup> &Fixups,
                               const MCSubtargetInfo &STI) const;

    unsigned getMemSrcValue(const MCInst &MI, unsigned OpIdx,
                            SmallVectorImpl<MCFixup> &Fixups,
                            const MCSubtargetInfo &STI) const;

    unsigned getBranch26TargetOpValue(const MCInst &MI, unsigned OpIdx,
                                      SmallVectorImpl<MCFixup> &Fixups,
                                      const MCSubtargetInfo &STI) const;

    unsigned getBranch19TargetOpValue(const MCInst &MI, unsigned OpIdx,
                                      SmallVectorImpl<MCFixup> &Fixups,
                                      const MCSubtargetInfo &STI) const;

    void EmitByte(unsigned char C, raw_ostream &OS) const { 
        OS << (char)C; 
    }

    void EmitConstant(uint64_t Val, unsigned Size, raw_ostream &OS) const {
        /// Output the constant in BIG endian byte order.
        for (unsigned i = 0; i != Size; ++i) {
            unsigned Shift = (Size - 1 - i) * 8;
            EmitByte((Val >> Shift) & 0xff, OS);
        }
    }
  
    void encodeInstruction(const MCInst &MI, raw_ostream &OS,
                           SmallVectorImpl<MCFixup> &Fixups,
                           const MCSubtargetInfo &STI) const override;
};
} // end of anonymous namespace

MCCodeEmitter *llvm::createFISCMCCodeEmitter(const MCInstrInfo &MCII, const MCRegisterInfo &MRI, MCContext &Ctx) {
    return new FISCMCCodeEmitter(MCII, Ctx);
}

/// getMachineOpValue - Return binary encoding of operand. If the machine
/// operand requires relocation, record the relocation and return zero.
unsigned FISCMCCodeEmitter::getMachineOpValue(const MCInst &MI,
                                              const MCOperand &MO,
                                              SmallVectorImpl<MCFixup> &Fixups,
                                              const MCSubtargetInfo &STI) const 
{
    if (MO.isReg())
        return CTX.getRegisterInfo()->getEncodingValue(MO.getReg());

    if (MO.isImm())
        return static_cast<unsigned>(MO.getImm());

    assert(MO.isExpr() && "unknown operand kind in printOperand");

    const MCExpr *Expr = MO.getExpr();
    MCExpr::ExprKind Kind = Expr->getKind();
        
    if (Kind == MCExpr::Binary) {
        Expr = static_cast<const MCBinaryExpr*>(Expr)->getLHS();
        Kind = Expr->getKind();
    }

    assert (Kind == MCExpr::SymbolRef);

    unsigned FixupKind;
    
    switch (cast<MCSymbolRefExpr>(Expr)->getKind()) {
    default:
        llvm_unreachable("Unknown fixup kind!");
    case MCSymbolRefExpr::VK_FISC_Q1:
        FixupKind = FISC::fixup_fisc_mov_q1_pcrel;
        break;
    case MCSymbolRefExpr::VK_FISC_Q2:
        FixupKind = FISC::fixup_fisc_mov_q2_pcrel;
        break;
    case MCSymbolRefExpr::VK_FISC_Q3:
        FixupKind = FISC::fixup_fisc_mov_q3_pcrel;
        break;
    case MCSymbolRefExpr::VK_FISC_Q4:
        FixupKind = FISC::fixup_fisc_mov_q4_pcrel;
        break;
    case MCSymbolRefExpr::VK_FISC_CALL26:
        FixupKind = FISC::fixup_fisc_call26_pcrel;
        break;
    case MCSymbolRefExpr::VK_FISC_CALL19:
        FixupKind = FISC::fixup_fisc_call19_pcrel;
        break;
    case MCSymbolRefExpr::VK_FISC_9BIT:
        FixupKind = FISC::fixup_fisc_9bit_address;
        break;
    }

    Fixups.push_back(MCFixup::create(0, MO.getExpr(), MCFixupKind(FixupKind)));
    return 0;
}

unsigned FISCMCCodeEmitter::getMemSrcValue(const MCInst &MI, unsigned OpIdx,
                                           SmallVectorImpl<MCFixup> &Fixups,
                                           const MCSubtargetInfo &STI) const 
{
    unsigned Bits = 0;
    const MCOperand &RegMO = MI.getOperand(OpIdx);
    const MCOperand &ImmMO = MI.getOperand(OpIdx + 1);
    assert(ImmMO.getImm() >= 0);
    Bits |= (getMachineOpValue(MI, RegMO, Fixups, STI) << 9);
    Bits |= (unsigned)ImmMO.getImm() & 0x1ff;
    return Bits;
}

unsigned FISCMCCodeEmitter::getBranch26TargetOpValue(const MCInst &MI, unsigned OpIdx,
                                                     SmallVectorImpl<MCFixup> &Fixups,
                                                     const MCSubtargetInfo &STI) const
{
    const MCOperand &MO = MI.getOperand(OpIdx);
    
    if(MO.isImm()) return MO.getImm();

    assert(MO.isExpr() && "getBranch26TargetOpValue expects only expressions");

    const MCExpr *Expr = MO.getExpr();
    Fixups.push_back(MCFixup::create(0, Expr, MCFixupKind(FISC::fixup_fisc_call26_pcrel)));
    return 0;
}

unsigned FISCMCCodeEmitter::getBranch19TargetOpValue(const MCInst &MI, unsigned OpIdx,
                                                     SmallVectorImpl<MCFixup> &Fixups,
                                                     const MCSubtargetInfo &STI) const
{
    const MCOperand &MO = MI.getOperand(OpIdx);

    if (MO.isImm()) return MO.getImm();

    assert(MO.isExpr() && "getBranch19TargetOpValue expects only expressions");

    const MCExpr *Expr = MO.getExpr();
    Fixups.push_back(MCFixup::create(0, Expr, MCFixupKind(FISC::fixup_fisc_call19_pcrel)));
    return 0;
}

void FISCMCCodeEmitter::encodeInstruction(const MCInst &MI, raw_ostream &OS,
                                          SmallVectorImpl<MCFixup> &Fixups,
                                          const MCSubtargetInfo &STI) const 
{
    const MCInstrDesc &Desc = MCII.get(MI.getOpcode());
    if (Desc.getSize() != 4) {
        llvm_unreachable("Unexpected instruction size!");
    }

    const uint32_t Binary = getBinaryCodeForInstr(MI, Fixups, STI);
    EmitConstant(Binary, Desc.getSize(), OS);
    
    ++MCNumEmitted;
}

#include "FISCGenMCCodeEmitter.inc"
