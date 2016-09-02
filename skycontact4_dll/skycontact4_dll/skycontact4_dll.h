// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SKYCONTACT4_DLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SKYCONTACT4_DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef SKYCONTACT4_DLL_EXPORTS
#define SKYCONTACT4_DLL_API __declspec(dllexport)
#else
#define SKYCONTACT4_DLL_API __declspec(dllimport)
#endif

// This class is exported from the skycontact4_dll.dll
class SKYCONTACT4_DLL_API Cskycontact4_dll {
public:
	Cskycontact4_dll(void);
	// TODO: add your methods here.
};

extern SKYCONTACT4_DLL_API int nskycontact4_dll;

SKYCONTACT4_DLL_API int fnskycontact4_dll(void);
