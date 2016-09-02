// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the GOODRECVRELAY4_DLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// GOODRECVRELAY4_DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef GOODRECVRELAY4_DLL_EXPORTS
#define GOODRECVRELAY4_DLL_API __declspec(dllexport)
#else
#define GOODRECVRELAY4_DLL_API __declspec(dllimport)
#endif

// This class is exported from the goodrecvrelay4_dll.dll
class GOODRECVRELAY4_DLL_API Cgoodrecvrelay4_dll {
public:
	Cgoodrecvrelay4_dll(void);
	// TODO: add your methods here.
};

extern GOODRECVRELAY4_DLL_API int ngoodrecvrelay4_dll;

GOODRECVRELAY4_DLL_API int fngoodrecvrelay4_dll(void);
