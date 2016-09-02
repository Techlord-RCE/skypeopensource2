// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the GOODSENDRELAY4_DLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// GOODSENDRELAY4_DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef GOODSENDRELAY4_DLL_EXPORTS
#define GOODSENDRELAY4_DLL_API __declspec(dllexport)
#else
#define GOODSENDRELAY4_DLL_API __declspec(dllimport)
#endif

// This class is exported from the goodsendrelay4_dll.dll
class GOODSENDRELAY4_DLL_API Cgoodsendrelay4_dll {
public:
	Cgoodsendrelay4_dll(void);
	// TODO: add your methods here.
};

extern GOODSENDRELAY4_DLL_API int ngoodsendrelay4_dll;

GOODSENDRELAY4_DLL_API int fngoodsendrelay4_dll(void);
