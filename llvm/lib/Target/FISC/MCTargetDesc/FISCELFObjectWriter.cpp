//===-- FISCELFObjectWriter.cpp - FISC ELF Writer ---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/FISCMCTargetDesc.h"
#include "MCTargetDesc/FISCFixupKinds.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
    class FISCELFObjectWriter : public MCELFObjectTargetWriter {
    public:
        FISCELFObjectWriter(uint8_t OSABI);

        virtual ~FISCELFObjectWriter();

        unsigned GetRelocType(const MCValue &Target, const MCFixup &Fixup, bool IsPCRel) const override;
    };
} // end of anonymous namespace

unsigned FISCELFObjectWriter::GetRelocType(const MCValue &Target, const MCFixup &Fixup, bool IsPCRel) const {
    if (!IsPCRel)
        llvm_unreachable("Only dealing with PC-relative fixups for now");

    unsigned Type = 0;
    switch ((unsigned)Fixup.getKind()) {
    default:
        llvm_unreachable("Unimplemented");
    case FISC::fixup_fisc_mov_q1_pcrel:
        Type = ELF::R_FISC_MOV_Q1;
        break;
    case FISC::fixup_fisc_mov_q2_pcrel:
        Type = ELF::R_FISC_MOV_Q2;
        break;
    case FISC::fixup_fisc_mov_q3_pcrel:
        Type = ELF::R_FISC_MOV_Q3;
        break;
    case FISC::fixup_fisc_mov_q4_pcrel:
        Type = ELF::R_FISC_MOV_Q4;
        break;
    case FISC::fixup_fisc_call26_pcrel:
        Type = ELF::R_FISC_CALL26;
        break;
    case FISC::fixup_fisc_call19_pcrel:
        Type = ELF::R_FISC_CALL19;
        break;
    case FISC::fixup_fisc_9bit_address:
        Type = ELF::R_FISC_9_ADDRESS;
        break;
    case FISC::fixup_fisc_6bit_shamt:
        Type = ELF::R_FISC_6_SHAMT;
        break;
    case FISC::fixup_fisc_12bit_imm:
        Type = ELF::R_FISC_12_IMM;
        break;
    }
    return Type;
}

FISCELFObjectWriter::FISCELFObjectWriter(uint8_t OSABI)
    : MCELFObjectTargetWriter(/*Is64Bit*/ true, OSABI, ELF::EM_FISC, /*HasRelocationAddend*/ false) {}

FISCELFObjectWriter::~FISCELFObjectWriter() {}

MCObjectWriter *llvm::createFISCELFObjectWriter(raw_pwrite_stream &OS, uint8_t OSABI) {
    MCELFObjectTargetWriter *MOTW = new FISCELFObjectWriter(OSABI);
    return createELFObjectWriter(MOTW, OS, /*IsLittleEndian=*/ false);
}
