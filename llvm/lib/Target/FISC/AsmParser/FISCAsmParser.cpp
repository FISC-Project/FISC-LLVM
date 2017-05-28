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
#include <iostream>

using namespace llvm;

#define DEBUG_TYPE "fisc - asmparser"

namespace {
class FISCAssemblerOptions {
public:
    FISCAssemblerOptions() : reorder(true), macro(true) { }

    bool isReorder()    { return reorder;  }
    void setReorder()   { reorder = true;  }
    void setNoreorder() { reorder = false; }

    bool isMacro()    { return macro;  }
    void setMacro()   { macro = true;  }
    void setNomacro() { macro = false; }

private:
    bool reorder;
    bool macro;
};
}

namespace {
class FISCAsmParser : public MCTargetAsmParser {
    MCAsmParser &Parser;
    FISCAssemblerOptions Options;

#define GET_ASSEMBLER_HEADER
#include "FISCGenAsmMatcher.inc"

private:
    bool MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                                 OperandVector &Operands, MCStreamer &Out,
                                 uint64_t &ErrorInfo,
                                 bool MatchingInlineAsm) override;

    bool ParseRegister(unsigned &RegNo, SMLoc &StartLoc, SMLoc &EndLoc) override;

    bool ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
                          SMLoc NameLoc, OperandVector &Operands) override;

    bool ParseDirective(AsmToken DirectiveID) override;
    
    bool isOperandRegister(const AsmToken &Tok);

    FISCAsmParser::OperandMatchResultTy parseMemOperand(OperandVector &);

    bool ParseOperand(OperandVector &Operands, StringRef Mnemonic);

    bool ParseRegisterOperand(OperandVector *Operands, StringRef Mnemonic);

    bool reportParseError(StringRef ErrorMsg);

    bool parseMemOffset(const MCExpr *&Res);
    bool parseRelocOperand(const MCExpr *&Res);

    const MCExpr *evaluateRelocExpr(const MCExpr *Expr, StringRef RelocStr, std::string Identifier);

    bool parseDirectiveWord(unsigned Size, SMLoc L);
    bool parseDirectiveSet();
    bool parseSetMacroDirective();
    bool parseSetNoMacroDirective();
    bool parseSetReorderDirective();
    bool parseSetNoReorderDirective();
    
    FISC::CondCodes parseCondCodeString(StringRef Cond);

    int matchRegisterName(StringRef Symbol);

    int matchRegisterByNumber(unsigned RegNum, StringRef Mnemonic);

    unsigned getReg(int RC, int RegNo);

public:
    FISCAsmParser(const MCSubtargetInfo &sti, MCAsmParser &parser,
                  const MCInstrInfo &MII, const MCTargetOptions &Options)
    : MCTargetAsmParser(Options, sti), Parser(parser) 
    {
        // Initialize the set of available features.
        setAvailableFeatures(ComputeAvailableFeatures(getSTI().getFeatureBits()));
    }

    MCAsmParser &getParser() const { return Parser; }
    MCAsmLexer &getLexer() const { return Parser.getLexer(); }
};
}

namespace {
/// FISCOperand - Instances of this class represent a parsed FISC machine
/// instruction.
class FISCOperand : public MCParsedAsmOperand {
    enum KindTy {
        k_CondCode,
        k_Immediate,
        k_Memory,
        k_PostIndexRegister,
        k_Register,
        k_Token
    } Kind;

public:
    FISCOperand(KindTy K) : MCParsedAsmOperand(), Kind(K) {}

    struct Token {
        const char *Data;
        unsigned Length;
    };
    struct PhysRegOp {
        unsigned RegNum; /// Register Number
    };
    struct ImmOp {
        const MCExpr *Val;
    };
    struct MemOp {
        unsigned Base;
        const MCExpr *Off;
    };
    struct CondCodeOp {
        FISC::CondCodes Code;
    };

    union {
        struct Token Tok;
        struct PhysRegOp Reg;
        struct ImmOp Imm;
        struct MemOp Mem;
        struct CondCodeOp CondCode;
    };

    SMLoc StartLoc, EndLoc;

public:
    void addRegOperands(MCInst &Inst, unsigned N) const {
        assert(N == 1 && "Invalid number of operands!");
        Inst.addOperand(MCOperand::createReg(getReg()));
    }

    void addExpr(MCInst &Inst, const MCExpr *Expr) const {
        // Add as immediate when possible.  Null MCExpr = 0.
        if (Expr == 0)
            Inst.addOperand(MCOperand::createImm(0));
        else if (const MCConstantExpr *CE = dyn_cast<MCConstantExpr>(Expr))
            Inst.addOperand(MCOperand::createImm(CE->getValue()));
        else
            Inst.addOperand(MCOperand::createExpr(Expr));
    }

    void addImmOperands(MCInst &Inst, unsigned N) const {
        assert(N == 1 && "Invalid number of operands!");
        const MCExpr *Expr = getImm();
        addExpr(Inst, Expr);
    }

    void addMemOperands(MCInst &Inst, unsigned N) const {
        assert(N == 2 && "Invalid number of operands!");

        Inst.addOperand(MCOperand::createReg(getMemBase()));

        const MCExpr *Expr = getMemOff();
        addExpr(Inst, Expr);
    }

    bool isReg()   const { return Kind == k_Register;  }
    bool isImm()   const { return Kind == k_Immediate; }
    bool isToken() const { return Kind == k_Token;     }
    bool isMem()   const { return Kind == k_Memory;    }
    bool isCond()  const { return Kind == k_CondCode;  }

    StringRef getToken() const {
        assert(Kind == k_Token && "Invalid access!");
        return StringRef(Tok.Data, Tok.Length);
    }

    unsigned getReg() const {
        assert((Kind == k_Register) && "Invalid access!");
        return Reg.RegNum;
    }

    const MCExpr *getImm() const {
        assert((Kind == k_Immediate) && "Invalid access!");
        return Imm.Val;
    }

    unsigned getMemBase() const {
        assert((Kind == k_Memory) && "Invalid access!");
        return Mem.Base;
    }

    const MCExpr *getMemOff() const {
        assert((Kind == k_Memory) && "Invalid access!");
        return Mem.Off;
    }

    static std::unique_ptr<FISCOperand> CreateToken(StringRef Str, SMLoc S) {
        auto Op = make_unique<FISCOperand>(k_Token);
        Op->Tok.Data = Str.data();
        Op->Tok.Length = Str.size();
        Op->StartLoc = S;
        Op->EndLoc = S;
        return Op;
    }

    /// Internal constructor for register kinds
    static std::unique_ptr<FISCOperand> CreateReg(unsigned RegNum, SMLoc S, SMLoc E) {
        auto Op = make_unique<FISCOperand>(k_Register);
        Op->Reg.RegNum = RegNum;
        Op->StartLoc = S;
        Op->EndLoc = E;
        return Op;
    }
    
    static std::unique_ptr<FISCOperand> CreateImm(const MCExpr *Val, SMLoc S, SMLoc E) {
        auto Op = make_unique<FISCOperand>(k_Immediate);
        Op->Imm.Val = Val;
        Op->StartLoc = S;
        Op->EndLoc = E;
        return Op;
    }

    static std::unique_ptr<FISCOperand> CreateMem(unsigned Base, const MCExpr *Off, SMLoc S, SMLoc E) {
        auto Op = make_unique<FISCOperand>(k_Memory);
        Op->Mem.Base = Base;
        Op->Mem.Off = Off;
        Op->StartLoc = S;
        Op->EndLoc = E;
        return Op;
    }

    static std::unique_ptr<FISCOperand> CreateCondCode(FISC::CondCodes Code, SMLoc S, SMLoc E) {
        auto Op = make_unique<FISCOperand>(k_CondCode);
        Op->CondCode.Code = Code;
        Op->StartLoc = S;
        Op->EndLoc = E;
        return Op;
    }

    /// getStartLoc - Get the location of the first token of this operand.
    SMLoc getStartLoc() const { return StartLoc; }
    /// getEndLoc - Get the location of the last token of this operand.
    SMLoc getEndLoc() const { return EndLoc; }

    virtual void print(raw_ostream &OS) const {
        llvm_unreachable("unimplemented!");
    }
};
}

bool FISCAsmParser::MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                                            OperandVector &Operands,
                                            MCStreamer &Out,
                                            uint64_t &ErrorInfo,
                                            bool MatchingInlineAsm) 
{
    MCInst Inst;
    unsigned MatchResult = MatchInstructionImpl(Operands, Inst, ErrorInfo, MatchingInlineAsm);
    switch (MatchResult) {
    default: break;
    case Match_Success: {
        Inst.setLoc(IDLoc);
        Out.EmitInstruction(Inst, getSTI());
        return false;
    }
    case Match_MissingFeature:
        Error(IDLoc, "instruction requires a CPU feature not currently enabled");
        return true;
    case Match_InvalidOperand: {
        SMLoc ErrorLoc = IDLoc;
        if (ErrorInfo != ~0U) {
            if (ErrorInfo >= Operands.size())
                return Error(IDLoc, "too few operands for instruction");

            ErrorLoc = ((FISCOperand &)*Operands[ErrorInfo]).getStartLoc();
            if (ErrorLoc == SMLoc()) ErrorLoc = IDLoc;
        }
        return Error(ErrorLoc, "invalid operand for instruction");
    }
    case Match_MnemonicFail:
        return Error(IDLoc, "invalid instruction");
    }
    return true;
}

int FISCAsmParser::matchRegisterName(StringRef Name) {
    int CC = StringSwitch<unsigned>(Name)
        .Case("x0",  FISC::X0)
        .Case("x1",  FISC::X1)
        .Case("x2",  FISC::X2)
        .Case("x3",  FISC::X3)
        .Case("x4",  FISC::X4)
        .Case("x5",  FISC::X5)
        .Case("x6",  FISC::X6)
        .Case("x7",  FISC::X7)
        .Case("x8",  FISC::X8)
        .Case("x9",  FISC::X9)
        .Case("x10", FISC::X10)
        .Case("x11", FISC::X11)
        .Case("x12", FISC::X12)
        .Case("x13", FISC::X13)
        .Case("x14", FISC::X14)
        .Case("x15", FISC::X15)
        .Case("ip0", FISC::IP0)
        .Case("ip1", FISC::IP1)
        .Case("x18", FISC::X18)
        .Case("x19", FISC::X19)
        .Case("x20", FISC::X20)
        .Case("x21", FISC::X21)
        .Case("x22", FISC::X22)
        .Case("x23", FISC::X23)
        .Case("x24", FISC::X24)
        .Case("x25", FISC::X25)
        .Case("x26", FISC::X26)
        .Case("x27", FISC::X27)
        .Case("sp",  FISC::SP)
        .Case("fp",  FISC::FP)
        .Case("lr",  FISC::LR)
        .Case("xzr", FISC::XZR)
        .Default(-1);
    return CC;
}

unsigned FISCAsmParser::getReg(int RC, int RegNo) {
    return *(getContext().getRegisterInfo()->getRegClass(RC).begin() + RegNo);
}

int FISCAsmParser::matchRegisterByNumber(unsigned RegNum, StringRef Mnemonic) {
    if (RegNum > 31)
        return -1;
    return getReg(FISC::GRRegsRegClassID, RegNum);
}

bool FISCAsmParser::ParseRegisterOperand(OperandVector *Operands, StringRef Mnemonic) {
    SMLoc S = Parser.getTok().getLoc();
    const AsmToken &Tok = Parser.getTok();
    int RegNo = -1;

    if (Tok.is(AsmToken::Identifier))
        RegNo = matchRegisterName(Tok.getString().lower());
    else if (Tok.is(AsmToken::Integer))
        RegNo = matchRegisterByNumber(static_cast<unsigned>(Tok.getIntVal()), Mnemonic.lower());

    if (RegNo == -1)
        return true;

    if(Operands) {
        Operands->push_back(FISCOperand::CreateReg(RegNo, S, Parser.getTok().getLoc()));
        Parser.Lex(); // Eat register token.
    }
    return false;
}

bool FISCAsmParser::isOperandRegister(const AsmToken &Tok) {
    std::string token_str = std::string(Tok.getString());
    return token_str[0] == 'x' || token_str == "lr" || token_str == "sp" || token_str == "fp" || token_str == "ip0" || token_str == "ip1";
}

bool FISCAsmParser::ParseOperand(OperandVector &Operands, StringRef Mnemonic) {
    DEBUG(dbgs() << "ParseOperand\n");
    // Check if the current operand has a custom associated parser, if so, try to
    // custom parse the operand, or fallback to the general approach.
    OperandMatchResultTy ResTy = MatchOperandParserImpl(Operands, Mnemonic);
    if (ResTy == MatchOperand_Success)
        return false;
    // If there wasn't a custom match, try the generic matcher below. Otherwise,
    // there was a match, but an error occurred, in which case, just return that
    // the operand parsing failed.
    if (ResTy == MatchOperand_ParseFail)
        return true;

    DEBUG(dbgs() << ".. Generic Parser\n");

    std::string token_str = std::string(Parser.getTok().getString());

    switch (getLexer().getKind()) {
    default:
        Error(Parser.getTok().getLoc(), "unexpected token in operand");
        return true;
    case AsmToken::Identifier:
    case AsmToken::LParen:
    case AsmToken::Minus:
    case AsmToken::Plus:
    case AsmToken::Integer:
    case AsmToken::String: { // quoted label names
        // parse register operand
        if (isOperandRegister(Parser.getTok()))
            return ParseRegisterOperand(&Operands, Mnemonic);
        
        // Ignore the word lsl
        if (token_str == "lsl")
            Parser.Lex(); // eat the lsl word

        const MCExpr *IdVal;
        SMLoc S = Parser.getTok().getLoc();
        if (getParser().parseExpression(IdVal))
            return true;

        if (IdVal->getKind() == MCExpr::ExprKind::SymbolRef) {
            StringRef Opcode = StringRef(((FISCOperand*)(Operands[0].get()))->Tok.Data,
                                         ((FISCOperand*)(Operands[0].get()))->Tok.Length);
            // TODO: We found a symbol. We need to figure out the fixup type for this operand by using the opcode string
        }
    
        SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
        Operands.push_back(FISCOperand::CreateImm(IdVal, S, E));
        return false;
    }
    case AsmToken::Percent: {
        // it is a symbol reference or constant expression
        const MCExpr *IdVal;
        SMLoc S = Parser.getTok().getLoc(); // start location of the operand
        if (parseRelocOperand(IdVal))
            return true;

        SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
        Operands.push_back(FISCOperand::CreateImm(IdVal, S, E));
        return false;
    }
    }
    return true;
}

const MCExpr *FISCAsmParser::evaluateRelocExpr(const MCExpr *Expr, StringRef RelocStr, std::string Identifier) {
    MCSymbolRefExpr::VariantKind Kind =
        StringSwitch<MCSymbolRefExpr::VariantKind>(RelocStr)
        .Case("mov_q1", MCSymbolRefExpr::VK_FISC_Q1)
        .Case("mov_q2", MCSymbolRefExpr::VK_FISC_Q2)
        .Case("mov_q3", MCSymbolRefExpr::VK_FISC_Q3)
        .Case("mov_q4", MCSymbolRefExpr::VK_FISC_Q4)
        .Case("call26", MCSymbolRefExpr::VK_FISC_CALL26)
        .Case("call19", MCSymbolRefExpr::VK_FISC_CALL19)
        .Case("ldst9",  MCSymbolRefExpr::VK_FISC_9BIT)
        .Case("shmt6",  MCSymbolRefExpr::VK_FISC_6BIT)
        .Case("imm12",  MCSymbolRefExpr::VK_FISC_12BIT)
        .Default(MCSymbolRefExpr::VK_FISC_NONE);

    assert(Kind != MCSymbolRefExpr::VK_FISC_NONE);

    MCContext & Ctx = getContext();
    return MCSymbolRefExpr::create(Ctx.getOrCreateSymbol(Identifier), Kind, Ctx);
}

bool FISCAsmParser::parseRelocOperand(const MCExpr *&Res) {
    Parser.Lex(); // eat % token
    const AsmToken &Tok = Parser.getTok(); // get next token, operation
    if (Tok.isNot(AsmToken::Identifier))
        return true;

    std::string Str = Tok.getIdentifier().str();
    std::string LabelStr;

    Parser.Lex(); // eat identifier
    
    // now make expression from the rest of the operand
    const MCExpr *IdVal;
    SMLoc EndLoc;

    if (getLexer().getKind() == AsmToken::LParen) {
        Parser.Lex(); // eat '(' token

        if (getLexer().getKind() == AsmToken::Dot)
            Parser.Lex(); // eat '.' token

        LabelStr = Tok.getIdentifier().str();

        if (getParser().parseParenExpression(IdVal, EndLoc))
            return true;
    }
    else
        return true; // parenthesis must follow reloc operand

    Res = evaluateRelocExpr(IdVal, Str, LabelStr);
    return false;
}

bool FISCAsmParser::ParseRegister(unsigned &RegNo, SMLoc &StartLoc, SMLoc &EndLoc) {
    StartLoc = Parser.getTok().getLoc();
    RegNo = ParseRegisterOperand(nullptr, "");
    EndLoc = Parser.getTok().getLoc();
    return (RegNo == (unsigned)-1);
}

bool FISCAsmParser::parseMemOffset(const MCExpr *&Res) {
    SMLoc S;

    switch (getLexer().getKind()) {
    default:
        return true;
    case AsmToken::Integer:
    case AsmToken::Minus:
    case AsmToken::Plus:
        return (getParser().parseExpression(Res));
    case AsmToken::Percent:
        return parseRelocOperand(Res);
    case AsmToken::LParen:
        return false; // it's probably assuming 0
    }
    return true;
}

FISCAsmParser::OperandMatchResultTy FISCAsmParser::parseMemOperand(OperandVector &Operands) {
    // Parse [
    if(std::string(Parser.getTok().getString()) != "[") {
        Error(Parser.getTok().getLoc(), "'[' expected");
        Parser.Lex(); // Eat '[' token.
        return MatchOperand_ParseFail;
    }

    Parser.Lex(); // eat [
    
    const MCExpr *IdVal = 0;
    const AsmToken &Tok = Parser.getTok(); 
    SMLoc S = Tok.getLoc();
    
    // Parse 1st operand (base register)

    if (isOperandRegister(Tok)) {
        if (ParseRegisterOperand(&Operands, "")) {
            Error(Parser.getTok().getLoc(), "unexpected token in operand");
            return MatchOperand_ParseFail;
        }
    }
    else {
        Error(Parser.getTok().getLoc(), "unexpected token in operand");
        return MatchOperand_ParseFail;
    }

    // Parse comma

    const AsmToken &Tok2 = Parser.getTok(); // get next token
    if (Tok2.isNot(AsmToken::Comma)) {
        Error(Parser.getTok().getLoc(), "',' expected");
        return MatchOperand_ParseFail;
    }

    SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);

    Parser.Lex(); // Eat ',' token.

    // Parse 2nd operand (offset)

    if (parseMemOffset(IdVal))
        return MatchOperand_ParseFail;

    // Parse ]

    if (std::string(Parser.getTok().getString()) != "]") {
        Error(Parser.getTok().getLoc(), "']' expected");
        Parser.Lex(); // Eat ']' token.
        return MatchOperand_ParseFail;
    }
    
    Parser.Lex(); // Eat ']' token.
    
    if (!IdVal)
        IdVal = MCConstantExpr::create(0, getContext());

    // Replace the register operand with the memory operand.
    std::unique_ptr<FISCOperand> op(static_cast<FISCOperand *>(Operands.back().release()));
    int RegNo = op->getReg();
    // remove register from operands
    Operands.pop_back();
    // and add memory operand
    Operands.push_back(FISCOperand::CreateMem(RegNo, IdVal, S, E));
    return MatchOperand_Success;
}

bool FISCAsmParser::reportParseError(StringRef ErrorMsg) {
    SMLoc Loc = getLexer().getLoc();
    Parser.eatToEndOfStatement();
    return Error(Loc, ErrorMsg);
}

bool FISCAsmParser::parseSetReorderDirective() {
    Parser.Lex();
    // if this is not the end of the statement, report error
    if (getLexer().isNot(AsmToken::EndOfStatement)) {
        reportParseError("unexpected token in statement");
        return false;
    }
    Options.setReorder();
    Parser.Lex(); // Consume the EndOfStatement
    return false;
}

bool FISCAsmParser::parseSetNoReorderDirective() {
    Parser.Lex();
    // if this is not the end of the statement, report error
    if (getLexer().isNot(AsmToken::EndOfStatement)) {
        reportParseError("unexpected token in statement");
        return false;
    }
    Options.setNoreorder();
    Parser.Lex(); // Consume the EndOfStatement
    return false;
}

bool FISCAsmParser::parseSetMacroDirective() {
    Parser.Lex();
    // if this is not the end of the statement, report error
    if (getLexer().isNot(AsmToken::EndOfStatement)) {
        reportParseError("unexpected token in statement");
        return false;
    }
    Options.setMacro();
    Parser.Lex(); // Consume the EndOfStatement
    return false;
}

bool FISCAsmParser::parseSetNoMacroDirective() {
    Parser.Lex();
    // if this is not the end of the statement, report error
    if (getLexer().isNot(AsmToken::EndOfStatement)) {
        reportParseError("`noreorder' must be set before `nomacro'");
        return false;
    }
    if (Options.isReorder()) {
        reportParseError("`noreorder' must be set before `nomacro'");
        return false;
    }
    Options.setNomacro();
    Parser.Lex(); // Consume the EndOfStatement
    return false;
}

bool FISCAsmParser::parseDirectiveSet() {
    // get next token
    const AsmToken &Tok = Parser.getTok();

    if (Tok.getString() == "reorder")
        return parseSetReorderDirective();
    else if (Tok.getString() == "noreorder")
        return parseSetNoReorderDirective();
    else if (Tok.getString() == "macro")
        return parseSetMacroDirective();
    else if (Tok.getString() == "nomacro")
        return parseSetNoMacroDirective();
    return true;
}

bool FISCAsmParser::parseDirectiveWord(unsigned Size, SMLoc L) {
    if (getLexer().isNot(AsmToken::EndOfStatement)) {
        for (;;) {
            const MCExpr *Value;
            if (getParser().parseExpression(Value))
                return true;

            getParser().getStreamer().EmitValue(Value, Size);

            if (getLexer().is(AsmToken::EndOfStatement))
                break;

            if (getLexer().isNot(AsmToken::Comma))
                return Error(L, "unexpected token in directive");
            Parser.Lex();
        }
    }
    Parser.Lex();
    return false;
}

bool FISCAsmParser::ParseDirective(AsmToken DirectiveID) {
    StringRef IDVal = DirectiveID.getString();

    if (IDVal == ".ent") {
        // ignore this directive for now
        Parser.Lex();
        return false;
    }

    if (IDVal == ".end") {
        // ignore this directive for now
        Parser.Lex();
        return false;
    }

    if (IDVal == ".frame") {
        // ignore this directive for now
        Parser.eatToEndOfStatement();
        return false;
    }

    if (IDVal == ".set") {
        return parseDirectiveSet();
    }

    if (IDVal == ".fmask") {
        // ignore this directive for now
        Parser.eatToEndOfStatement();
        return false;
    }

    if (IDVal == ".mask") {
        // ignore this directive for now
        Parser.eatToEndOfStatement();
        return false;
    }

    if (IDVal == ".gpword") {
        // ignore this directive for now
        Parser.eatToEndOfStatement();
        return false;
    }

    if (IDVal == ".byte")
        return parseDirectiveWord(1, DirectiveID.getLoc());

    if (IDVal == ".half")
        return parseDirectiveWord(2, DirectiveID.getLoc());

    if (IDVal == ".word")
        return parseDirectiveWord(4, DirectiveID.getLoc());

    if (IDVal == ".nword")
        return parseDirectiveWord(8, DirectiveID.getLoc());

    if (IDVal == ".xword")
        return parseDirectiveWord(8, DirectiveID.getLoc());

    return true;
}

/// parseCondCodeString - Parse a Condition Code string.
FISC::CondCodes FISCAsmParser::parseCondCodeString(StringRef Cond) {
    FISC::CondCodes CC = StringSwitch<FISC::CondCodes>(Cond.lower())
        .Case("eq", FISC::CondCodes::COND_EQ)
        .Case("ne", FISC::CondCodes::COND_NE)
        .Case("cs", FISC::CondCodes::COND_GT)
        .Case("hs", FISC::CondCodes::COND_GT)
        .Case("cc", FISC::CondCodes::COND_LE)
        .Case("lo", FISC::CondCodes::COND_LE)
        .Case("ge", FISC::CondCodes::COND_GE)
        .Case("lt", FISC::CondCodes::COND_LT)
        .Case("gt", FISC::CondCodes::COND_GT)
        .Default(FISC::CondCodes::COND_INVAL);
    return CC;
}

bool FISCAsmParser::ParseInstruction(ParseInstructionInfo &Info, StringRef Name, SMLoc NameLoc, OperandVector &Operands) {
    // Replace ret mnemonic with br
    if (Name == "ret")
        Name = "br";

    Name = StringSwitch<StringRef>(Name.lower())
        .Case("beq", "b.eq")
        .Case("bne", "b.ne")
        .Case("bhs", "b.hs")
        .Case("bcs", "b.cs")
        .Case("blo", "b.lo")
        .Case("bcc", "b.cc")
        .Case("bmi", "b.mi")
        .Case("bpl", "b.pl")
        .Case("bvs", "b.vs")
        .Case("bvc", "b.vc")
        .Case("bhi", "b.hi")
        .Case("bls", "b.ls")
        .Case("bge", "b.ge")
        .Case("blt", "b.lt")
        .Case("bgt", "b.gt")
        .Case("ble", "b.le")
        .Case("bal", "b.al")
        .Case("bnv", "b.nv")
        .Default(Name);

    // Create the leading tokens for the mnemonic, split by '.' characters.
    size_t Start = 0, Next = Name.find('.');
    StringRef Head = Name.slice(Start, Next);

    Operands.push_back(FISCOperand::CreateToken(Head, NameLoc));

    // Handle condition codes for a branch mnemonic
    if (Head == "b" && Next != StringRef::npos) {
        Start = Next;
        Next = Name.find('.', Start + 1);
        Head = Name.slice(Start + 1, Next);

        SMLoc SuffixLoc = SMLoc::getFromPointer(NameLoc.getPointer() + (Head.data() - Name.data()));
        FISC::CondCodes CC = parseCondCodeString(Head);
        if (CC == FISC::CondCodes::COND_INVAL)
            return Error(SuffixLoc, "invalid condition code");

        const MCExpr * CC_Expr = MCConstantExpr::create((int64_t)CC, getContext());
        Operands.push_back(FISCOperand::CreateImm(CC_Expr, Parser.getTok().getLoc(), SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1)));
    }

    // Read the remaining operands.
    if (getLexer().isNot(AsmToken::EndOfStatement)) {
        // Read the first operand.
        if (ParseOperand(Operands, Name)) {
            SMLoc Loc = getLexer().getLoc();
            Parser.eatToEndOfStatement();
            return Error(Loc, "unexpected token in argument list");
        }

        while(getLexer().is(AsmToken::Comma)) {
            Parser.Lex(); // Eat the comma.

            // Parse and remember the operand.
            if (ParseOperand(Operands, Name)) {
                SMLoc Loc = getLexer().getLoc();
                Parser.eatToEndOfStatement();
                return Error(Loc, "unexpected token in argument list");
            }
        }
    }

    if (getLexer().isNot(AsmToken::EndOfStatement)) {
        SMLoc Loc = getLexer().getLoc();
        Parser.eatToEndOfStatement();
        return Error(Loc, "unexpected token in argument list");
    }

    Parser.Lex(); // Consume the EndOfStatement
    return false;
}

extern "C" void LLVMInitializeFISCAsmParser() {
    RegisterMCAsmParser<FISCAsmParser> X(TheFISCTarget);
}

#define GET_REGISTER_MATCHER
#define GET_MATCHER_IMPLEMENTATION
#include "FISCGenAsmMatcher.inc"
