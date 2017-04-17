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
def X0  : FISCReg<0,  "x0">;
def X1  : FISCReg<1,  "x1">;
def X2  : FISCReg<2,  "x2">;
def X3  : FISCReg<3,  "x3">;
def X4  : FISCReg<4,  "x4">;
def X5  : FISCReg<5,  "x5">;
def X6  : FISCReg<6,  "x6">;
def X7  : FISCReg<7,  "x7">;
def X8  : FISCReg<8,  "x8">;
def X9  : FISCReg<9,  "x9">;
def X10 : FISCReg<10, "x10">;
def X11 : FISCReg<11, "x11">;
def X12 : FISCReg<12, "x12">;
def X13 : FISCReg<13, "x13">;
def X14 : FISCReg<14, "x14">;
def X15 : FISCReg<15, "x15">;
def IP0 : FISCReg<16, "ip0">;
def IP1 : FISCReg<17, "ip1">;
def X18 : FISCReg<18, "x18">;
def X19 : FISCReg<19, "x19">;
def X20 : FISCReg<20, "x20">;
def X21 : FISCReg<21, "x21">;
def X22 : FISCReg<22, "x22">;
def X23 : FISCReg<23, "x23">;
def X24 : FISCReg<24, "x24">;
def X25 : FISCReg<25, "x25">;
def X26 : FISCReg<26, "x26">;
def X27 : FISCReg<27, "x27">;
def SP  : FISCReg<28, "sp">;
def FP  : FISCReg<29, "fp">;
def LR  : FISCReg<30, "lr">;
def XZR : FISCReg<31, "xzr">;

// Register classes
def GRRegs : RegisterClass<"FISC", [i64], 64,
    // Return values and arguments
    (add
        // General Purpose Registers:
        X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15,
    
        // Intra-Procedure-Call Scratch Registers:
        IP0, IP1,
    
        // General Purpose Registers:
        X18, X19, X20, X21, X22, X23, X24, X25, X26, X27,
    
        // Special "General Purpose" Registers:
        SP, FP, LR, XZR
    )>;
