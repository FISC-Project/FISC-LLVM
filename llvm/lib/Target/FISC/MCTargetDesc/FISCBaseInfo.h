//===-- FISCBaseInfo.h - Top level definitions for FISC -------- --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone helper functions and enum definitions for
// the FISC target useful for the compiler back-end and the MC libraries.
// As such, it deliberately does not include references to LLVM core
// code gen types, passes, etc..
//
//===----------------------------------------------------------------------===//

#ifndef FISCBASEINFO_H
#define FISCBASEINFO_H

#include "FISCMCTargetDesc.h"
#include "llvm/Support/ErrorHandling.h"

namespace llvm {

/// FISCII - This namespace holds all of the target specific flags that
/// instruction info tracks.
namespace FISCII {

    /// Target Operand Flag enum.
    enum TOF {
        //===------------------------------------------------------------------===//
        // FISC-Specific MachineOperand flags.
        //===------------------------------------------------------------------===//
        MO_NO_FLAG = 0,

        /// MO_Q1 - On a symbol operand, this represents a relocation containing
        /// lower 16 bit of the address. Used via movz instruction.
        MO_Q1 = 0x1,

        /// MO_Q2 - On a symbol operand, this represents a relocation containing
        /// 2nd lower 16 bit of the address. Used via movk instruction.
        MO_Q2 = 0x2,

        /// MO_Q3 - On a symbol operand, this represents a relocation containing
        /// 1st upper 16 bit of the address. Used via movk instruction.
        MO_Q3 = 0x4,

        /// MO_Q4 - On a symbol operand, this represents a relocation containing
        /// 2nd upper 16 bit of the address. Used via movk instruction.
        MO_Q4 = 0x8,

        /// MO_CALL26 - On a BL instruction, this represents a relocation for the 26 bit address
        MO_CALL26 = 0x10,

        /// MO_CALL19 - On a conditional branch instruction, this represents a relocation for the 19 bit address
        MO_CALL19 = 0x20,

        /// Flag for 9 bit addresses
        MO_9BIT = 0x40,

        /// Flag for 6 bit shamt values
        MO_6BIT = 0x80,

        /// Flag for 12 bit immediate values
        MO_12BIT = 0x100,
        
        /// Flag used when moving pc-relative 16-bit values into a GP register
        MO_MOVRZ = 0xF,

        /// MO_OPTION_MASK - Most flags are mutually exclusive; this mask selects
        /// just that part of the flag set.
        MO_OPTION_MASK = 0x1ff,

        /// It's undefined behaviour if an enum overflows the range between its
        /// smallest and largest values, but since these are |ed together, it can
        /// happen. Put a sentinel in (values of this enum are stored as "unsigned
        /// char").
        MO_UNUSED_MAXIMUM = 0xff
    };
} // end namespace FISCII
} // end namespace llvm

#endif
