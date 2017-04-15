//===-- FISCSelectionDAGInfo.h - FISC SelectionDAG Info -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the FISC subclass for TargetSelectionDAGInfo.
//
//===----------------------------------------------------------------------===//

#ifndef FISCSELECTIONDAGINFO_H
#define FISCSELECTIONDAGINFO_H

#include "llvm/Target/TargetSelectionDAGInfo.h"

namespace llvm {

class FISCSelectionDAGInfo : public TargetSelectionDAGInfo {
public:
  ~FISCSelectionDAGInfo();
};
}

#endif
