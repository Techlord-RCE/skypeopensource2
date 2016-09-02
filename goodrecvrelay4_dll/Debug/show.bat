@echo off

set PATH=%PATH%;"C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE"
set PATH=%PATH%;"C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\"

rem dumpbin.exe /exports /SYMBOLS /IMPORTS relayrecv4_dll.dll
rem set DevEnvDir=%VSINSTALLDIR%Common7\IDE

dumpbin.exe /exports /SYMBOLS goodrecvrelay4_dll.dll  > log_export.txt
