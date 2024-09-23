//#include <windows.h>
//#include <iostream>
//#include "InjectDll.h"
//using namespace std;
//#ifdef UNICODE
//#define tcin wcin
//#define tcout wcout
//#define tstring wstring
//#else
//#define tcin std::cin
//#define tcout std::cout
//#define tstring std::string
//#endif
//typedef NTSTATUS(WINAPI* LDRGETPROCEDUREADDRESS)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
//typedef VOID(WINAPI* RTLFREEUNICODESTRING)(_Inout_ PUNICODE_STRING UnicodeString);
//typedef VOID(WINAPI* RTLINITANSISTRING)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
//typedef NTSTATUS(WINAPI* RTLANSISTRINGTOUNICODESTRING)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
//typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
//typedef BOOL(APIENTRY* DLLMAIN)(LPVOID, DWORD, LPVOID);
//typedef NTSTATUS(WINAPI* NTALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
//typedef INT(WINAPI* MESSAGEBOXA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
//int main()
//{
//
//	INJECTPARAM m_injectparam;
//	
//	
//
//	HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
//
//
//	LDRGETPROCEDUREADDRESS Func_LdrGetProcedureAddress;
//	RTLFREEUNICODESTRING Func_RtlFreeUnicodeString;
//	RTLINITANSISTRING Func_RtlInitAnsiString;
//	NTALLOCATEVIRTUALMEMORY Func_NtAllocateVirtualMemory;
//	LDRLOADDLL Func_LdrLoadDll;
//	RTLANSISTRINGTOUNICODESTRING Func_RtlAnsiStringToUnicodeString;
//
//	Func_LdrGetProcedureAddress = (LDRGETPROCEDUREADDRESS)GetProcAddress(hNtDll, "LdrGetProcedureAddress");
//	Func_NtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
//	Func_LdrLoadDll = (LDRLOADDLL)GetProcAddress(hNtDll, "LdrLoadDll");
//	Func_RtlInitAnsiString = (RTLINITANSISTRING)GetProcAddress(hNtDll, "RtlInitAnsiString");
//	Func_RtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING)GetProcAddress(hNtDll, "RtlAnsiStringToUnicodeString");
//	Func_RtlFreeUnicodeString = (RTLFREEUNICODESTRING)GetProcAddress(hNtDll, "RtlFreeUnicodeString");
//
//
//	m_injectparam.Func_LdrGetProcedureAddress = Func_LdrGetProcedureAddress;
//	m_injectparam.Func_NtAllocateVirtualMemory = Func_NtAllocateVirtualMemory;
//	m_injectparam.Func_LdrLoadDll = Func_LdrLoadDll;
//	m_injectparam.Func_RtlInitAnsiString = Func_RtlInitAnsiString;
//	m_injectparam.Func_RtlAnsiStringToUnicodeString = Func_RtlAnsiStringToUnicodeString;
//	m_injectparam.Func_RtlFreeUnicodeString = Func_RtlFreeUnicodeString;
//
//
//
//
//	TCHAR ProcessName[0x20];
//	TCHAR PE_Path[0x200];
//	SIZE_T Oep;
//	tcout << "请输入需要注入的PE文件路径" << endl;
//	tcin.getline(PE_Path,0x200);
//	tcout << "请输入需要注入的程序名字" << endl;
//	tcin.getline(ProcessName, 0x20);
//	tcout << "请输入注入Dll的DllMain或者Exe的OEP" << endl;
//	tcin >> std::hex >> Oep;
//																		
//
//	BOOL Success = OpenPeFile(PE_Path);
//	if (!Success)
//	{
//		MessageBox(0, L"打开文件失败", 0, 0);
//	}
//	TargetPID = GetProcessIDByName(ProcessName);
//	Success = InjectDLL(TargetPID,m_injectparam);
//	if (!Success)
//	{
//		MessageBox(0, L"注入失败！", 0, 0);
//	}
//	
//	
//	CreateSafeThread((LPVOID)((SIZE_T)pRemoteMemory+ Oep), m_injectparam, TargetPID, ProcessName);
//
//	return 0;
//
//
//}
//
