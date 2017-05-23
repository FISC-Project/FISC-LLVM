//===-- FISCAsmParser.cpp - Parse FISC assembly to MCInst instructions ----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "FISC.h"
#include "MCTargetDesc/FISCMCTargetDesc.h"
#include "FISCRegisterInfo.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstBuilder.h"
#include "llvm/MC/MCParser/MCAsmLexer.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCTargetAsmParser.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCParser/MCAsmLexer.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

#define DEBUG_TYPE "fisc - asmparser"

///////////// TODO ///////////////

namespace {
class FISCAsmParser : public MCTargetAsmParser {
	MCAsmParser &Parser;

	bool MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
		                         OperandVector &Operands, MCStreamer &Out,
		                         uint64_t &ErrorInfo,
		                         bool MatchingInlineAsm) override;

	bool ParseRegister(unsigned &RegNo, SMLoc &StartLoc, SMLoc &EndLoc) override;

	bool ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
		                  SMLoc NameLoc, OperandVector &Operands) override;

	bool ParseDirective(AsmToken DirectiveID) override;

	void convertToMapAndConstraints(unsigned Kind, const OperandVector &Operands) override;

public:
	FISCAsmParser(const MCSubtargetInfo &sti, MCAsmParser &parser,
		const MCInstrInfo &MII, const MCTargetOptions &Options)
		: MCTargetAsmParser(Options, sti), Parser(parser) {
		// Initialize the set of available features.
		//setAvailableFeatures(ComputeAvailableFeatures(getSTI().getFeatureBits()));
	}
};
}

bool FISCAsmParser::MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
	OperandVector &Operands,
	MCStreamer &Out,
	uint64_t &ErrorInfo,
	bool MatchingInlineAsm) 
{
	return false;
}

bool FISCAsmParser::ParseRegister(unsigned &RegNo, SMLoc &StartLoc,
	SMLoc &EndLoc) 
{
	return false;
}

bool FISCAsmParser::ParseInstruction(ParseInstructionInfo &Info, StringRef Name, SMLoc NameLoc,
	                                 OperandVector &Operands) 
{
	return false;
}

bool FISCAsmParser::ParseDirective(AsmToken DirectiveID) {
	return false;
}

void FISCAsmParser::convertToMapAndConstraints(unsigned Kind, const OperandVector &Operands) {

}

extern "C" void LLVMInitializeFISCAsmParser() {
	RegisterMCAsmParser<FISCAsmParser> X(TheFISCTarget);
}