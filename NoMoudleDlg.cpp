
// NoMoudleDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "NoMoudle.h"
#include "NoMoudleDlg.h"
#include "afxdialogex.h"
#include "InjectDll.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CNoMoudleDlg 对话框



CNoMoudleDlg::CNoMoudleDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_NOMOUDLE_DIALOG, pParent)
	, DllPath(_T(""))
	, ProcessName(_T(""))
	, DllMain_RVA(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNoMoudleDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, DllPath);
	DDX_Text(pDX, IDC_EDIT2, ProcessName);
	//  DDX_Text(pDX, IDC_EDIT3, DllMain_RVA);
	DDX_Text(pDX, IDC_EDIT3, DllMain_RVA);
}

BEGIN_MESSAGE_MAP(CNoMoudleDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CNoMoudleDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CNoMoudleDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CNoMoudleDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CNoMoudleDlg 消息处理程序

BOOL CNoMoudleDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CNoMoudleDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CNoMoudleDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CNoMoudleDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CNoMoudleDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	CFileDialog dlg(TRUE,               // 打开文件对话框
		NULL,          // 默认扩展名为 "txt"
		NULL,               // 无初始文件名
		OFN_HIDEREADONLY | OFN_FILEMUSTEXIST,  // 标志：隐藏只读复选框，文件必须存在
		NULL, // 文件过滤器
		this);              // 父窗口为当前对话框

	if (dlg.DoModal())
	{
		DllPath = dlg.GetPathName();
	}
	UpdateData(FALSE);
}

INJECTPARAM m_injectparam;
void CNoMoudleDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	typedef NTSTATUS(WINAPI* LDRGETPROCEDUREADDRESS)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
	typedef VOID(WINAPI* RTLFREEUNICODESTRING)(_Inout_ PUNICODE_STRING UnicodeString);
	typedef VOID(WINAPI* RTLINITANSISTRING)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
	typedef NTSTATUS(WINAPI* RTLANSISTRINGTOUNICODESTRING)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
	typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
	typedef BOOL(APIENTRY* DLLMAIN)(LPVOID, DWORD, LPVOID);
	typedef NTSTATUS(WINAPI* NTALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
	typedef INT(WINAPI* MESSAGEBOXA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

	



	HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");


	LDRGETPROCEDUREADDRESS Func_LdrGetProcedureAddress;
	RTLFREEUNICODESTRING Func_RtlFreeUnicodeString;
	RTLINITANSISTRING Func_RtlInitAnsiString;
	NTALLOCATEVIRTUALMEMORY Func_NtAllocateVirtualMemory;
	LDRLOADDLL Func_LdrLoadDll;
	RTLANSISTRINGTOUNICODESTRING Func_RtlAnsiStringToUnicodeString;

	Func_LdrGetProcedureAddress = (LDRGETPROCEDUREADDRESS)GetProcAddress(hNtDll, "LdrGetProcedureAddress");
	Func_NtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
	Func_LdrLoadDll = (LDRLOADDLL)GetProcAddress(hNtDll, "LdrLoadDll");
	Func_RtlInitAnsiString = (RTLINITANSISTRING)GetProcAddress(hNtDll, "RtlInitAnsiString");
	Func_RtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING)GetProcAddress(hNtDll, "RtlAnsiStringToUnicodeString");
	Func_RtlFreeUnicodeString = (RTLFREEUNICODESTRING)GetProcAddress(hNtDll, "RtlFreeUnicodeString");


	m_injectparam.Func_LdrGetProcedureAddress = Func_LdrGetProcedureAddress;
	m_injectparam.Func_NtAllocateVirtualMemory = Func_NtAllocateVirtualMemory;
	m_injectparam.Func_LdrLoadDll = Func_LdrLoadDll;
	m_injectparam.Func_RtlInitAnsiString = Func_RtlInitAnsiString;
	m_injectparam.Func_RtlAnsiStringToUnicodeString = Func_RtlAnsiStringToUnicodeString;
	m_injectparam.Func_RtlFreeUnicodeString = Func_RtlFreeUnicodeString;



	
	UpdateData(TRUE);
	BOOL Success = OpenPeFile(DllPath.GetBuffer());
	if (!Success)
	{
		::MessageBox(0, TEXT("打开文件失败"), 0, 0);
		return;
	}
	TargetPID = GetProcessIDByName(ProcessName.GetBuffer());
	Success = InjectDLL(TargetPID, m_injectparam);
	if (!Success)
	{
		::MessageBox(0, TEXT("注入失败！"), 0, 0);
	}


}
#include <iostream>
#include <sstream>
#include <iomanip>



void CNoMoudleDlg::OnBnClickedButton3()
{
	//// TODO: 在此添加控件通知处理程序代码
	//SIZE_T Dll_Main;
	//sprintf(Dll_Main,TEXT("%x"),)
	long decimalValue = _tcstol(DllMain_RVA, nullptr, 16); // 转换为十进制
	bool Success = CreateSafeThread((LPVOID)((SIZE_T)pRemoteMemory + decimalValue), m_injectparam, TargetPID, ProcessName.GetBuffer());
	if (!Success)
	{
		::MessageBox(0, TEXT("启动失败！"), 0, 0);
	}
	else
		::MessageBox(0, TEXT("启动成功！"), 0, 0);
}
