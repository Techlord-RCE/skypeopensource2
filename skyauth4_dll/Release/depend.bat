@echo on

set PATH="C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE"
set PATH=%PATH%;"C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\"

dumpbin /DEPENDENTS skyauth4_dll.dll > log_depends.txt

