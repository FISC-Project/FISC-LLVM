//===- FISCDisassembler.cpp - Disassembler for FISC -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is part of the FISC Disassembler.
//
//===----------------------------------------------------------------------===//

#include "FISC.h"
#include "FISCRegisterInfo.h"
#include "FISCSubtarget.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCFixedLenDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

#define DEBUG_TYPE "fisc - disassembler"

typedef MCDisassembler::DecodeStatus DecodeStatus;

namespace {
class FISCDisassembler : public MCDisassembler {
public:
    FISCDisassembler(const MCSubtargetInfo &STI, MCContext &Ctx) :
        MCDisassembler(STI, Ctx) {}

    virtual ~FISCDisassembler() {}

    DecodeStatus getInstruction(MCInst &Instr, uint64_t &Size,
                                ArrayRef<uint8_t> Bytes, uint64_t Address,
                                raw_ostream &VStream,
                                raw_ostream &CStream) const override;
};
}

// Decoder tables for GPR registers
static const unsigned CPURegsTable[] = {
    FISC::X0,  FISC::X1,  FISC::X2,  FISC::X3,  FISC::X4,  FISC::X5, 
    FISC::X6,  FISC::X7,  FISC::X8,  FISC::X9,  FISC::X10, FISC::X11, 
    FISC::X12, FISC::X13, FISC::X14, FISC::X15,
    FISC::IP0, FISC::IP1,
    FISC::X18, FISC::X19, FISC::X20, FISC::X21, FISC::X22, FISC::X23,
    FISC::X24, FISC::X25, FISC::X26, FISC::X27,
    FISC::SP,  FISC::FP,  FISC::LR,  FISC::XZR
};

static DecodeStatus DecodeCPURegsRegisterClass(MCInst &Inst,
                                               unsigned RegNo,
                                               uint64_t Address,
                                               const void *Decoder);

static DecodeStatus DecodeGRRegsRegisterClass(MCInst &Inst,
                                              unsigned RegNo,
                                              uint64_t Address,
                                              const void *Decoder);

static DecodeStatus DecodeBranch26Target(MCInst &Inst,
                                         unsigned Insn,
                                         uint64_t Address,
                                         const void *Decoder);

static DecodeStatus DecodeJumpTarget(MCInst &Inst,
                                     unsigned Insn,
                                     uint64_t Address,
                                     const void *Decoder);

static DecodeStatus DecodeMem(MCInst &Inst,
                              unsigned Insn,
                              uint64_t Address,
                              const void *Decoder);

#include "FISCGenDisassemblerTables.inc"

static DecodeStatus DecodeCPURegsRegisterClass(MCInst &Inst,
                                               unsigned RegNo,
                                               uint64_t Address,
                                               const void *Decoder)
{
    if (RegNo > 31)
        return MCDisassembler::Fail;

    Inst.addOperand(MCOperand::createReg(CPURegsTable[RegNo]));
    return MCDisassembler::Success;
}

static DecodeStatus DecodeGRRegsRegisterClass(MCInst &Inst,
                                              unsigned RegNo,
                                              uint64_t Address,
                                              const void *Decoder)
{
    return DecodeCPURegsRegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeBranch26Target(MCInst &Inst,
                                         unsigned Insn,
                                         uint64_t Address,
                                         const void *Decoder)
{
    Inst.addOperand(MCOperand::createImm(SignExtend32<26>(Insn)));
    return MCDisassembler::Success;
}

static DecodeStatus DecodeJumpTarget(MCInst &Inst,
                                     unsigned Insn,
                                     uint64_t Address,
                                     const void *Decoder)
{
    unsigned JumpOffset = fieldFromInstruction(Insn, 0, 26);
    Inst.addOperand(MCOperand::createImm(JumpOffset));
    return MCDisassembler::Success;
}

static DecodeStatus DecodeCJumpTarget(MCInst &Inst,
                                      unsigned Insn,
                                      uint64_t Address,
                                      const void *Decoder)
{
    Inst.addOperand(MCOperand::createImm(SignExtend32<19>(Insn)));
    return MCDisassembler::Success;
}

static DecodeStatus DecodeMem(MCInst &Inst,
    unsigned Insn,
    uint64_t Address,
    const void *Decoder)
{
    int Reg = (int)fieldFromInstruction(Insn, 0, 5);
    int Offset = SignExtend32<16>((Insn & 0x1FF000) >> 12);
    int Base = (int)fieldFromInstruction(Insn, 5, 4);

    Inst.addOperand(MCOperand::createReg(CPURegsTable[Reg]));
    Inst.addOperand(MCOperand::createReg(CPURegsTable[Base]));
    Inst.addOperand(MCOperand::createImm(Offset));

    return MCDisassembler::Success;
}

/// Read four bytes from the ArrayRef and return 32 bit word sorted
static DecodeStatus readInstruction32(ArrayRef<uint8_t> Bytes, uint64_t Address,
                                      uint64_t &Size, uint32_t &Insn) 
{
    if (Bytes.size() < 4) {
        Size = 0;
        return MCDisassembler::Fail;
    }

    // Encoded as a big-endian 32-bit word in the stream.
    Insn = (Bytes[3] << 0)  |
           (Bytes[2] << 8)  |
           (Bytes[1] << 16) |
           (Bytes[0] << 24);

    return MCDisassembler::Success;
}

DecodeStatus FISCDisassembler::getInstruction(MCInst &Instr, uint64_t &Size,
                                              ArrayRef<uint8_t> Bytes, uint64_t Address,
                                              raw_ostream &VStream,
                                              raw_ostream &CStream) const 
{
    uint32_t Insn;
    DecodeStatus Result = readInstruction32(Bytes, Address, Size, Insn);
    if(Result == MCDisassembler::Fail)
        return Result;

    // Calling the auto-generated decoder function.
    Result = decodeInstruction(DecoderTableFISC32, Instr, Insn, Address, this, STI);
    if (Result != MCDisassembler::Fail) {
        Size = 4;
        return Result;
    }

    return MCDisassembler::Fail;
}

namespace llvm {
    extern Target TheFISCTarget;
}

static MCDisassembler * createFISCDisassebler(
    const Target & T,
    const MCSubtargetInfo &STI,
    MCContext &Ctx) 
{
    return new FISCDisassembler(STI, Ctx);
}

extern "C" void LLVMInitializeFISCDisassembler() {
    /// Register the Disassembler
    TargetRegistry::RegisterMCDisassembler(TheFISCTarget, createFISCDisassebler);
}