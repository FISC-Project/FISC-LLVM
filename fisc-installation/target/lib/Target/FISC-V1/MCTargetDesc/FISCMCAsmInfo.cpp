//===-- FISCMCAsmInfo.cpp - FISC asm properties -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "FISCMCAsmInfo.h"
#include "llvm/ADT/StringRef.h"
using namespace llvm;

void FISCMCAsmInfo::anchor() {}

FISCMCAsmInfo::FISCMCAsmInfo(const Triple &TT) {
	SupportsDebugInformation = true;
	Data8bitsDirective       = "\t.byte\t";
	Data16bitsDirective      = "\t.hword\t";
	Data32bitsDirective      = "\t.word\t";
	Data64bitsDirective      = "\t.dword\t";
	ZeroDirective            = "\t.space\t";
	CommentString            = "#";
	AscizDirective           = ".asciiz";

	HiddenVisibilityAttr            = MCSA_Invalid;
	HiddenDeclarationVisibilityAttr = MCSA_Invalid;
	ProtectedVisibilityAttr         = MCSA_Invalid;
}

