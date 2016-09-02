// skycontact4_dll.cpp : Defines the exported functions for the DLL application.
//

#include "skycontact4_dll.h"


// This is an example of an exported variable
SKYCONTACT4_DLL_API int nskycontact4_dll=0;

// This is an example of an exported function.
SKYCONTACT4_DLL_API int fnskycontact4_dll(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see skycontact4_dll.h for the class definition
Cskycontact4_dll::Cskycontact4_dll()
{
	return;
}
