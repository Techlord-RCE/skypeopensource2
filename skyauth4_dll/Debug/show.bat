@echo on

set PATH="C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE"
set PATH=%PATH%;"C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\"

rem dumpbin.exe /exports /SYMBOLS /IMPORTS skyauth4_dll.dll 

dumpbin.exe /exports /SYMBOLS skyauth4_dll.dll > log.txt
