@echo off

set PATH="C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE"
set PATH=%PATH%;"C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\"

rem dumpbin.exe /exports /SYMBOLS /IMPORTS skyrelay4_dll.dll

dumpbin.exe /exports /SYMBOLS skyrelay4_dll.dll > _log.txt
