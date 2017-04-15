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
}

unsigned FISCELFObjectWriter::GetRelocType(const MCValue &Target,
										  const MCFixup &Fixup,
										  bool IsPCRel) const 
{
  if (!IsPCRel)
	llvm_unreachable("Only dealying with PC-relative fixups for now");

  unsigned Type = 0;
  switch ((unsigned)Fixup.getKind()) {
  default:
	llvm_unreachable("Unimplemented");
  case FISC::fixup_FISC_mov_hi16_pcrel:
	Type = ELF::R_ARM_MOVT_PREL;
	break;
  case FISC::fixup_FISC_mov_lo16_pcrel:
	Type = ELF::R_ARM_MOVW_PREL_NC;
	break;
  }
  return Type;
}

FISCELFObjectWriter::FISCELFObjectWriter(uint8_t OSABI)
	: MCELFObjectTargetWriter(/*Is64Bit*/ false, OSABI, /*ELF::EM_FISC*/ ELF::EM_ARM,
							  /*HasRelocationAddend*/ false) {}

FISCELFObjectWriter::~FISCELFObjectWriter() {}

MCObjectWriter *llvm::createFISCELFObjectWriter(raw_pwrite_stream &OS, uint8_t OSABI) {
	MCELFObjectTargetWriter *MOTW = new FISCELFObjectWriter(OSABI);
	return createELFObjectWriter(MOTW, OS, /*IsLittleEndian=*/true);
}
