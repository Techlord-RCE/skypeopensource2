// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SKYAUTH4_DLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SKYAUTH4_DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef SKYAUTH4_DLL_EXPORTS
#define SKYAUTH4_DLL_API __declspec(dllexport)
#else
#define SKYAUTH4_DLL_API __declspec(dllimport)
#endif

// This class is exported from the skyauth4_dll.dll
class SKYAUTH4_DLL_API Cskyauth4_dll {
public:
	Cskyauth4_dll(void);
	// TODO: add your methods here.
};

extern SKYAUTH4_DLL_API int nskyauth4_dll;

SKYAUTH4_DLL_API int fnskyauth4_dll(void);
