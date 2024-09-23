#include <windows.h>
#include <winternl.h>



typedef NTSTATUS(WINAPI* LDRGETPROCEDUREADDRESS)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
typedef VOID(WINAPI* RTLFREEUNICODESTRING)(_Inout_ PUNICODE_STRING UnicodeString);
typedef VOID(WINAPI* RTLINITANSISTRING)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
typedef NTSTATUS(WINAPI* RTLANSISTRINGTOUNICODESTRING)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL(APIENTRY* DLLMAIN)(LPVOID, DWORD, LPVOID);
typedef NTSTATUS(WINAPI* NTALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
typedef INT(WINAPI* MESSAGEBOXA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

struct TypeOffset
{


	WORD Offset : 12;       // 低12位代表重定位地址
	WORD Type : 4;          // 高4位代表重定位类型
};
// 声明全局变量 (extern 关键字)
extern SIZE_T FileSize;
extern SIZE_T FileBase;
extern PVOID Stretch_Data;
extern PIMAGE_DOS_HEADER pDosHeader;
extern PIMAGE_FILE_HEADER pFileHead;
extern PIMAGE_SECTION_HEADER* Section;
extern LPVOID pRemoteMemory;
extern SIZE_T TargetPID;
extern PIMAGE_NT_HEADERS pNtHeader;
//#ifdef   _WIN64
//extern PIMAGE_NT_HEADERS pNtHeader;
//extern PIMAGE_OPTIONAL_HEADER pNt_Optional;
//#else
//extern PIMAGE_NT_HEADERS32 pNtHeader;
//extern PIMAGE_OPTIONAL_HEADER32 pNt_Optional;
//#endif


extern LDRGETPROCEDUREADDRESS Func_LdrGetProcedureAddress;
extern RTLFREEUNICODESTRING Func_RtlFreeUnicodeString;
extern RTLINITANSISTRING Func_RtlInitAnsiString;
extern NTALLOCATEVIRTUALMEMORY Func_NtAllocateVirtualMemory;
extern LDRLOADDLL Func_LdrLoadDll;
extern RTLANSISTRINGTOUNICODESTRING Func_RtlAnsiStringToUnicodeString;

typedef struct _INJECTPARAM
{
	PVOID lpFileData;   //我们要注射的DLL内容
	DWORD dwDataLength; //我们要注射的DLL长度
	DWORD dwTargetPID;  //我们要注射的进程PID

	LDRGETPROCEDUREADDRESS       Func_LdrGetProcedureAddress;
	NTALLOCATEVIRTUALMEMORY      Func_NtAllocateVirtualMemory;
	LDRLOADDLL                   Func_LdrLoadDll;
	RTLINITANSISTRING            Func_RtlInitAnsiString;
	RTLANSISTRINGTOUNICODESTRING Func_RtlAnsiStringToUnicodeString;
	RTLFREEUNICODESTRING         Func_RtlFreeUnicodeString;
	MESSAGEBOXA                  Func_MessageBoxA;


} INJECTPARAM;

VOID Analyze_PE(PCHAR& Data);
void Stretch_PE();
SIZE_T GetProcessIDByName(TCHAR* processName);
VOID RepairFixReloc(TCHAR new_file[], SIZE_T NewImageBase);
SIZE_T RVAtoFOA(SIZE_T rva);
BOOL OpenPeFile(TCHAR* FileName);
bool InjectDLL(DWORD processID, INJECTPARAM m_injectparam);
VOID Repair_IAT(INJECTPARAM m_injectparam);
BOOL CreateSafeThread(IN LPVOID lpFunction, INJECTPARAM Injectparam, SIZE_T TargetPID,TCHAR* ProcessName);

