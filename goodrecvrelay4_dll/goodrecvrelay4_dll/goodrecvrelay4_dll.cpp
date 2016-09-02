// goodrecvrelay4_dll.cpp : Defines the exported functions for the DLL application.
//

#include "goodrecvrelay4_dll.h"


// This is an example of an exported variable
GOODRECVRELAY4_DLL_API int ngoodrecvrelay4_dll=0;

// This is an example of an exported function.
GOODRECVRELAY4_DLL_API int fngoodrecvrelay4_dll(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see goodrecvrelay4_dll.h for the class definition
Cgoodrecvrelay4_dll::Cgoodrecvrelay4_dll()
{
	return;
}
