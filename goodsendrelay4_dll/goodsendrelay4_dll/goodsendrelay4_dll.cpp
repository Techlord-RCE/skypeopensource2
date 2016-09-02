// goodsendrelay4_dll.cpp : Defines the exported functions for the DLL application.
//

#include "goodsendrelay4_dll.h"


// This is an example of an exported variable
GOODSENDRELAY4_DLL_API int ngoodsendrelay4_dll=0;

// This is an example of an exported function.
GOODSENDRELAY4_DLL_API int fngoodsendrelay4_dll(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see goodsendrelay4_dll.h for the class definition
Cgoodsendrelay4_dll::Cgoodsendrelay4_dll()
{
	return;
}
