//===- FISCCallingConv.td - Calling Conventions for FISC -*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// This describes the calling conventions for FISC architecture.
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// FISC Return Value Calling Convention
//===----------------------------------------------------------------------===//
def RetCC_FISC : CallingConv<[
    // i64 are returned in registers X0, X1 .. X7
    CCIfType<[i64], CCAssignToReg<[X0, X1, X2, X3, X4, X5, X6, X7]>>,

    // Integer values get stored in stack slots that are 8 bytes in
    // size and 8-byte aligned.
    CCIfType<[i64], CCAssignToStack<8, 8>>
]>;

//===----------------------------------------------------------------------===//
// FISC Argument Calling Conventions
//===----------------------------------------------------------------------===//
def CC_FISC : CallingConv<[
    // Promote i8/i16/i32 arguments to i64.
    CCIfType<[i8, i16, i32], CCPromoteToType<i64>>,
    
    // Integer values get stored in stack slots that are 8 bytes in
    // size and 8-byte aligned.
    CCIfType<[i64], CCAssignToStack<8, 8>>,

    // The first 8 integer arguments are passed in integer registers.
    CCIfType<[i64], CCAssignToReg<[X0, X1, X2, X3, X4, X5, X6, X7]>>
]>;

def CC_Save : CalleeSavedRegs<(add LR, X19, X20, X21, X22, X23, X24, X25, X26, X27)>;
