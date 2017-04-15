//===-- FISCMCAsmInfo.h - FISC asm properties --------------------*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the FISCMCAsmInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef FISCTARGETASMINFO_H
#define FISCTARGETASMINFO_H

#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm {
	class StringRef;
	class Target;
	class Triple;

	class FISCMCAsmInfo : public MCAsmInfoELF {
		virtual void anchor();

	public:
		explicit FISCMCAsmInfo(const Triple &TT);
	};
} // namespace llvm

#endif
