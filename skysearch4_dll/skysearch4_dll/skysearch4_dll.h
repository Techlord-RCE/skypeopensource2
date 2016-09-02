// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SKYSEARCH4_DLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SKYSEARCH4_DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef SKYSEARCH4_DLL_EXPORTS
#define SKYSEARCH4_DLL_API __declspec(dllexport)
#else
#define SKYSEARCH4_DLL_API __declspec(dllimport)
#endif

// This class is exported from the skysearch4_dll.dll
class SKYSEARCH4_DLL_API Cskysearch4_dll {
public:
	Cskysearch4_dll(void);
	// TODO: add your methods here.
};

extern SKYSEARCH4_DLL_API int nskysearch4_dll;

SKYSEARCH4_DLL_API int fnskysearch4_dll(void);
