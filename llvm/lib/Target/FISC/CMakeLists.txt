set(LLVM_TARGET_DEFINITIONS FISC.td)

tablegen(LLVM FISCGenRegisterInfo.inc -gen-register-info)
tablegen(LLVM FISCGenInstrInfo.inc -gen-instr-info)
tablegen(LLVM FISCGenAsmMatcher.inc -gen-asm-matcher)
tablegen(LLVM FISCGenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM FISCGenDAGISel.inc -gen-dag-isel)
tablegen(LLVM FISCGenCallingConv.inc -gen-callingconv)
tablegen(LLVM FISCGenSubtargetInfo.inc -gen-subtarget)
tablegen(LLVM FISCGenMCCodeEmitter.inc -gen-emitter)
tablegen(LLVM FISCGenCodeEmitter.inc -gen-emitter)
tablegen(LLVM FISCGenMCPseudoLowering.inc -gen-pseudo-lowering)
tablegen(LLVM FISCGenDisassemblerTables.inc -gen-disassembler)
add_public_tablegen_target(FISCCommonTableGen)

add_llvm_target(FISCCodeGen
  FISCSubtarget.cpp
  FISCTargetMachine.cpp
  FISCRegisterInfo.cpp
  FISCInstrInfo.cpp
  FISCFrameLowering.cpp
  FISCISelLowering.cpp
  FISCSelectionDAGInfo.cpp
  FISCISelDAGToDAG.cpp
  FISCAsmPrinter.cpp
  FISCMCInstLower.cpp
  FISCDelaySlotFiller.cpp
  FISCMachineFunctionInfo.cpp
  )

add_subdirectory(AsmParser)
add_subdirectory(Disassembler)
add_subdirectory(InstPrinter)
add_subdirectory(TargetInfo)
add_subdirectory(MCTargetDesc)
