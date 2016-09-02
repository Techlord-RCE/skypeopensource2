// skysearch4_dll.cpp : Defines the exported functions for the DLL application.
//

#include "skysearch4_dll.h"


// This is an example of an exported variable
SKYSEARCH4_DLL_API int nskysearch4_dll=0;

// This is an example of an exported function.
SKYSEARCH4_DLL_API int fnskysearch4_dll(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see skysearch4_dll.h for the class definition
Cskysearch4_dll::Cskysearch4_dll()
{
	return;
}
