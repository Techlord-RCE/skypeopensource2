// skyauth4_dll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "skyauth4_dll.h"


// This is an example of an exported variable
SKYAUTH4_DLL_API int nskyauth4_dll=0;

// This is an example of an exported function.
SKYAUTH4_DLL_API int fnskyauth4_dll(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see skyauth4_dll.h for the class definition
Cskyauth4_dll::Cskyauth4_dll()
{
	return;
}
