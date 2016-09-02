// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SKYRELAY4_DLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SKYRELAY4_DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef SKYRELAY4_DLL_EXPORTS
#define SKYRELAY4_DLL_API __declspec(dllexport)
#else
#define SKYRELAY4_DLL_API __declspec(dllimport)
#endif

// This class is exported from the skyrelay4_dll.dll
class SKYRELAY4_DLL_API Cskyrelay4_dll {
public:
	Cskyrelay4_dll(void);
	// TODO: add your methods here.
};

extern SKYRELAY4_DLL_API int nskyrelay4_dll;

SKYRELAY4_DLL_API int fnskyrelay4_dll(void);
