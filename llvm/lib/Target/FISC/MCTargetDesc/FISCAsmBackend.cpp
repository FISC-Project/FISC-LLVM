//===-- FISCAsmBackend.cpp - FISC Assembler Backend -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/FISCMCTargetDesc.h"
#include "MCTargetDesc/FISCFixupKinds.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDirectives.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCMachObjectWriter.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/ELF.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MachO.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
class FISCELFObjectWriter : public MCELFObjectTargetWriter {
public:
    FISCELFObjectWriter(uint8_t OSABI)
      : MCELFObjectTargetWriter(/*Is64Bit*/ false, OSABI, ELF::EM_FISC, /*HasRelocationAddend*/ false) {}
};

class FISCAsmBackend : public MCAsmBackend {
public:
    FISCAsmBackend(const Target &T, const StringRef TT) : MCAsmBackend() {}

    ~FISCAsmBackend() {}

    unsigned getNumFixupKinds() const override {
        return FISC::NumTargetFixupKinds;
    }

    const MCFixupKindInfo &getFixupKindInfo(MCFixupKind Kind) const override {
        const static MCFixupKindInfo Infos[FISC::NumTargetFixupKinds] = {
            /// This table *must* be in the order that the fixup_* kinds are defined in
            /// FISCFixupKinds.h.
            ///
            /// Name                      Offset (bits) Size (bits)     Flags
            { "fixup_fisc_mov_q1_pcrel", 0, 64, MCFixupKindInfo::FKF_IsPCRel },
            { "fixup_fisc_mov_q2_pcrel", 0, 64, MCFixupKindInfo::FKF_IsPCRel },
            { "fixup_fisc_mov_q3_pcrel", 0, 64, MCFixupKindInfo::FKF_IsPCRel },
            { "fixup_fisc_mov_q4_pcrel", 0, 64, MCFixupKindInfo::FKF_IsPCRel },
            { "fixup_fisc_call26_pcrel", 0, 64, MCFixupKindInfo::FKF_IsPCRel },
            { "fixup_fisc_call19_pcrel", 0, 64, MCFixupKindInfo::FKF_IsPCRel },
            { "fixup_fisc_9bit_address", 0, 64, MCFixupKindInfo::FKF_IsPCRel },
        };

        if (Kind < FirstTargetFixupKind)
            return MCAsmBackend::getFixupKindInfo(Kind);

        assert(unsigned(Kind - FirstTargetFixupKind) < getNumFixupKinds() && "Invalid kind!");
        return Infos[Kind - FirstTargetFixupKind];
    }

    /// processFixupValue - Target hook to process the literal value of a fixup if necessary.
    void processFixupValue(const MCAssembler &Asm, const MCAsmLayout &Layout,
                           const MCFixup &Fixup, const MCFragment *DF,
                           const MCValue &Target, uint64_t &Value,
                           bool &IsResolved) override;

    void applyFixup(const MCFixup &Fixup, char *Data, unsigned DataSize, uint64_t Value, bool IsPCRel) const override;

    bool mayNeedRelaxation(const MCInst &Inst) const override { 
        return false; 
    }

    bool fixupNeedsRelaxation(const MCFixup &Fixup, uint64_t Value,
                              const MCRelaxableFragment *DF,
                              const MCAsmLayout &Layout) const override 
    {
        return false;
    }

    void relaxInstruction(const MCInst &Inst, MCInst &Res) const override 
    {
        // Do nothing
    }

    bool writeNopData(uint64_t Count, MCObjectWriter *OW) const override 
    {
        if (Count == 0)
            return true;
        return false;
    }

    unsigned getPointerSize() const { 
        return 8; 
    }
};
} // end of anonymous namespace

static unsigned adjustFixupValue(const MCFixup &Fixup, uint64_t Value, MCContext *Ctx = NULL) {
    switch ((unsigned)Fixup.getKind()) {
    default:
        llvm_unreachable("Unknown fixup kind!");
    case FISC::fixup_fisc_mov_q4_pcrel:
        return ((Value >>= 48) & 0xFFFF) << 5;
    case FISC::fixup_fisc_mov_q3_pcrel:
        return ((Value >>= 32) & 0xFFFF) << 5;
    case FISC::fixup_fisc_mov_q2_pcrel:
        return ((Value >>= 16) & 0xFFFF) << 5;
    case FISC::fixup_fisc_mov_q1_pcrel:
        return (Value & 0xFFFF) << 5;
    case FISC::fixup_fisc_call26_pcrel:
        return Value & 0x3FFFFFF;
    case FISC::fixup_fisc_call19_pcrel:
        return (Value & 0x7FFFF) << 5;
    case FISC::fixup_fisc_9bit_address:
        return (Value & 0x1FF) << 12;
    }
    return Value;
}

void FISCAsmBackend::processFixupValue(const MCAssembler &Asm,
                                       const MCAsmLayout &Layout,
                                       const MCFixup &Fixup,
                                       const MCFragment *DF,
                                       const MCValue &Target, uint64_t &Value,
                                       bool &IsResolved) 
{
    /// We always have resolved fixups for now.
    IsResolved = true;

    /// At this point we'll ignore the value returned by adjustFixupValue as
    /// we are only checking if the fixup can be applied correctly.
    (void)adjustFixupValue(Fixup, Value, &Asm.getContext());
}

void FISCAsmBackend::applyFixup(const MCFixup &Fixup, char *Data,
                                unsigned DataSize, uint64_t Value,
                                bool isPCRel) const 
{
    unsigned NumBytes = 4;

    printf("\n\nFIXUP: %d VALUE: %d ", Fixup.getKind(), Value);

    Value = adjustFixupValue(Fixup, Value);

    printf("AFTER: %d\n\n", Value);

    if (!Value)
        return; /// Doesn't change encoding.

    unsigned Offset = Fixup.getOffset();
    assert(Offset + NumBytes <= DataSize && "Invalid fixup offset!");

    /// For each byte of the fragment that the fixup touches, mask in the bits from
    /// the fixup value. The Value has been "split up" into the appropriate
    /// bitfields above.
    for (unsigned i = 0; i != NumBytes; ++i)
        Data[Offset + i] |= uint8_t((Value >> ((NumBytes - i - 1) * 8)) & 0xff);
}

namespace {
class ELFFISCAsmBackend : public FISCAsmBackend {
public:
    uint8_t OSABI;
    ELFFISCAsmBackend(const Target &T, const StringRef TT, uint8_t _OSABI)
        : FISCAsmBackend(T, TT), OSABI(_OSABI) {}

    MCObjectWriter *createObjectWriter(raw_pwrite_stream &OS) const override {
        return createFISCELFObjectWriter(OS, OSABI);
    }
};

} // end of anonymous namespace

MCAsmBackend *llvm::createFISCAsmBackend(const Target &T,
                                         const MCRegisterInfo &MRI,
                                         const Triple &TT, StringRef CPU) 
{
    const uint8_t ABI = MCELFObjectTargetWriter::getOSABI(TT.getOS());
    return new ELFFISCAsmBackend(T, TT.getTriple(), ABI);
}
