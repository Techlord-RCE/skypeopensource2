// skyrelay4_dll.cpp : Defines the exported functions for the DLL application.
//
#include "skyrelay4_dll.h"


// This is an example of an exported variable
SKYRELAY4_DLL_API int nskyrelay4_dll=0;

// This is an example of an exported function.
SKYRELAY4_DLL_API int fnskyrelay4_dll(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see skyrelay4_dll.h for the class definition
Cskyrelay4_dll::Cskyrelay4_dll()
{
	return;
}
