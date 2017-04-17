@cd "%~dp0"
@echo off
@cls

@printf "================================================\n"
@printf "> Installing FISC target into the LLVM backend\n"
@printf "================================================\n"
mkdir build
xcopy /e /y fisc-installation\registry llvm
xcopy /e /y fisc-installation\target   llvm
printf "@cd ""%%%%~dp0""\n@echo off\n\ncd build\n\ncmake -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD=FISC  -G ""Visual Studio 14 2015 Win64"" ../llvm\n\n@cd ""%%%%~dp0""" > run-make-gen.bat
@printf "====================================\n"

@printf "\n> Done!"

@printf "\nNext steps:\n\t1- Run 'run-make-gen.bat/sh/py' once\n\t2- TODO (We'll add a script for building on windows/linux without an IDE)\n"

@cd "%~dp0"