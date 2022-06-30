
// MExampleDlg.h: 头文件
//

#pragma once


// CMExampleDlg 对话框
class CMExampleDlg : public CDialogEx
{
// 构造
public:
	CMExampleDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MEXAMPLE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_CListShow;
	afx_msg void OnNMCustomdrawListShow(NMHDR* pNMHDR, LRESULT* pResult);


public:
	static void notification(const char* describe, bool isDebug);
	afx_msg void OnNMRClickListShow(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnMenuRefresh();
};
