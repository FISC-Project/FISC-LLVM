//===-- FISCFixupKinds.h - FISC-Specific Fixup Entries ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_FISCFIXUPKINDS_H
#define LLVM_FISCFIXUPKINDS_H

#include "llvm/MC/MCFixup.h"

namespace llvm {
namespace FISC {
	enum Fixups {
		fixup_FISC_mov_hi16_pcrel = FirstTargetFixupKind,
		fixup_FISC_mov_lo16_pcrel,

		// Marker
		LastTargetFixupKind,
		NumTargetFixupKinds = LastTargetFixupKind - FirstTargetFixupKind
	};
}
}

#endif

