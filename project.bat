@echo off

set root=%cd%
set tool=%cd%\tools

:help
echo "0: help"
echo "1: clear exe"
echo "2: build all (include 3, 4)"
echo "9: quit"

:interact
cd %root%
set /p opt="Select to do: "
if %opt% equ 1 (
    goto clear_exe
) else if %opt% equ 2 (
    goto build_all
) else if %opt% equ 9 (
    goto quit
) else (
    goto help
)

:clear_exe
cd %root%
call clear.bat
goto interact

:build_all
rem build tools
cd %tool%
cl dump.c
cl trans.c
rem build shellcode
cd %root%\shellcode
cl /c /GS- /Ob1 code.c
link /entry:ShellCode /subsystem:console code.obj
%tool%\dump.exe /f:code.exe /s:.code /ob:code.bin
%tool%\trans.exe code.bin > %root%\shellcode.c
rem build generator
cd %root%
cl gen.c
rem build bin file
.\gen.exe
goto interact

:quit
echo "See you next time!"
