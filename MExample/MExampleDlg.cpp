
// MExampleDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MExample.h"
#include "MExampleDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

enum 
{
	ON_LIST_SHOW_DESCRIBE=0,
	ON_LIST_SHOW_STATUS,
};

std::tuple<int, const char*, int> g_colum_info[] =
{
	{ON_LIST_SHOW_DESCRIBE, "describe", 500},
	{ON_LIST_SHOW_STATUS,	"status", 100},
};


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


// CMExampleDlg 对话框



CMExampleDlg::CMExampleDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MEXAMPLE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMExampleDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_SHOW, m_CListShow);
}

BEGIN_MESSAGE_MAP(CMExampleDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_SHOW, &CMExampleDlg::OnNMCustomdrawListShow)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_SHOW, &CMExampleDlg::OnNMRClickListShow)
	ON_COMMAND(ID_MENU_REFRESH, &CMExampleDlg::OnMenuRefresh)
END_MESSAGE_MAP()


// CMExampleDlg 消息处理程序

BOOL CMExampleDlg::OnInitDialog()
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

	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标


	if (m_CListShow.m_hWnd != nullptr)
	{
		m_CListShow.SetExtendedStyle(LVS_EX_FULLROWSELECT);
		for (auto& item : g_colum_info)
		{
			m_CListShow.InsertColumn(std::get<0>(item), std::get<1>(item), LVCFMT_LEFT, std::get<2>(item));
		}
	}

	m_CListShow.DeleteAllItems();
	theApp.antiDebug->execute(notification);

	return TRUE;
}

void CMExampleDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CMExampleDlg::OnPaint()
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
HCURSOR CMExampleDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


#pragma warning(push)
#pragma warning(disable: 4244)
void CMExampleDlg::OnNMCustomdrawListShow(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	*pResult = CDRF_DODEFAULT;

	if (CDDS_PREPAINT == pLVCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pLVCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYSUBITEMDRAW;
	}
	else if ((CDDS_ITEMPREPAINT | CDDS_SUBITEM) == pLVCD->nmcd.dwDrawStage)
	{                                                              
		pLVCD->clrTextBk = RGB(0, 0, 0);
		pLVCD->clrText = 0;

		auto is = m_CListShow.GetItemData(pLVCD->nmcd.dwItemSpec);

		if (pLVCD->iSubItem == ON_LIST_SHOW_STATUS)
		{
			pLVCD->clrText = is ? RGB(255, 0, 0) : RGB(0, 255, 0);
		}
		else
		{
			pLVCD->clrText = RGB(255, 255, 255);
		}

		*pResult = CDRF_DODEFAULT;
	}
}
#pragma warning(pop)

void CMExampleDlg::notification(const char* describe, bool isDebug)
{
	auto pThis = (CMExampleDlg*)theApp.m_pMainWnd;

	auto count = pThis->m_CListShow.GetItemCount();
	pThis->m_CListShow.InsertItem(count, describe);
	pThis->m_CListShow.SetItemText(count, ON_LIST_SHOW_STATUS, isDebug ? "[ BAD ]" : "[ GOOD ]");
	pThis->m_CListShow.SetItemData(count, isDebug);
}


void CMExampleDlg::OnNMRClickListShow(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	*pResult = 0;

	CMenu Menu;
	CPoint p;
	CMenu* pMenu = NULL;

	Menu.LoadMenu(IDR_MENU_LIST_SHOW);
	pMenu = Menu.GetSubMenu(0);
	if (pMenu)
	{
		GetCursorPos(&p);
		pMenu->TrackPopupMenu(TPM_LEFTALIGN, p.x, p.y, this);
	}
}


void CMExampleDlg::OnMenuRefresh()
{
	m_CListShow.DeleteAllItems();
	theApp.antiDebug->execute(notification);
}
