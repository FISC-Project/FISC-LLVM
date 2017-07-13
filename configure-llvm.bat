@CD "%~dp0"
@ECHO OFF
@CLS

if NOT EXIST build (
	mkdir build
)

cd build

cmake -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=FISC -G "Visual Studio 14 2015 Win64" ../llvm

@cd "%~dp0"

if NOT EXIST "FISC Target" (
	@MKLINK /D "FISC Target" llvm\lib\Target\FISC>nul
	@MKLINK "LLVM Solution.sln" build\LLVM.sln>nul
)