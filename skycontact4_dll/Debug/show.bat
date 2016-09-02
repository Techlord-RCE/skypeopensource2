@echo off

set PATH="C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE"
set PATH=%PATH%;"C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\"

rem dumpbin.exe /exports /SYMBOLS /IMPORTS skycontact4_dll.dll

dumpbin.exe /exports /SYMBOLS skycontact4_dll.dll > log.txt
