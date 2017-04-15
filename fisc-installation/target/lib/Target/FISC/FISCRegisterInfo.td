//===-- FISCRegisterInfo.td - FISC Register defs ---------*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  Declarations that describe the FISC register file 
//===----------------------------------------------------------------------===//

class FISCReg<bits<16> Enc, string n> : Register<n> {
  let HWEncoding = Enc;
  let Namespace = "FISC";
}

// CPU registers
def R0  : FISCReg< 0, "r0">;
def R1  : FISCReg< 1, "r1">;
def R2  : FISCReg< 2, "r2">;
def R3  : FISCReg< 3, "r3">;
def R4  : FISCReg< 4, "r4">;
def R5  : FISCReg< 5, "r5">;
def R6  : FISCReg< 6, "r6">;
def R7  : FISCReg< 7, "r7">;
def R8  : FISCReg< 8, "r8">;
def R9  : FISCReg< 9, "r9">;

def SP  : FISCReg<13, "sp">;
def LR  : FISCReg<14, "lr">;

def CPSR  : FISCReg<16, "cpsr">;

// Register classes.
//
def GRRegs : RegisterClass<"FISC", [i32], 32,
  // Return values and arguments
  (add R0, R1, R2, R3,
       R4, R5, R6, R7, R8, R9, SP)>;
