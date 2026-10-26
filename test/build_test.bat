@echo off
rem Builds and runs LargeBlocksTest.exe (DGMalloc's chunked large blocks under 4 threads of alloc / free).
setlocal
set VS=C:\Program Files\Microsoft Visual Studio\18\Community
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
if not exist out mkdir out
cl /nologo /O2 /EHsc /std:c++17 /MT /DNDEBUG /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DDGMALLOC_KEEP_ALIVE_ON_EXIT /DDGMALLOC_VALIDATE_FREELIST ^
   /I..\third_party\mimalloc\include /Foout\ /Feout\LargeBlocksTest.exe LargeBlocksTest.cpp ..\third_party\mimalloc\src\static.c psapi.lib advapi32.lib
if errorlevel 1 exit /b 1
out\LargeBlocksTest.exe
