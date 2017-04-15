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

		MO_NO_FLAG = 0,

		/// MO_LO16 - On a symbol operand, this represents a relocation containing
		/// lower 16 bit of the address. Used only via movw instruction.
		MO_LO16 = 0x1,

		/// MO_HI16 - On a symbol operand, this represents a relocation containing
		/// higher 16 bit of the address. Used only via movt instruction.
		MO_HI16 = 0x2,

		/// MO_OPTION_MASK - Most flags are mutually exclusive; this mask selects
		/// just that part of the flag set.
		MO_OPTION_MASK = 0x7f,

		// It's undefined behaviour if an enum overflows the range between its
		// smallest and largest values, but since these are |ed together, it can
		// happen. Put a sentinel in (values of this enum are stored as "unsigned
		// char").
		MO_UNUSED_MAXIMUM = 0xff
	};
} // end namespace FISCII

} // end namespace llvm;

#endif
