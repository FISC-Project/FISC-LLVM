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
        fixup_fisc_mov_q1_pcrel = FirstTargetFixupKind,
        fixup_fisc_mov_q2_pcrel,
        fixup_fisc_mov_q3_pcrel,
        fixup_fisc_mov_q4_pcrel,
        fixup_fisc_call26_pcrel,
        fixup_fisc_call19_pcrel,
        fixup_fisc_9bit_address,

        /// Marker
        LastTargetFixupKind,
        NumTargetFixupKinds = LastTargetFixupKind - FirstTargetFixupKind
    };
}
} // end namespace llvm

#endif

