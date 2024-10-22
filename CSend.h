#pragma once


// CSend 对话框

class CSend : public CDialogEx
{
	DECLARE_DYNAMIC(CSend)

public:
	CSend(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CSend();
	
	int StartSend();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SEND_DIALOG };
#endif

protected:
	HICON m_hIcon;

	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	// 填写目的ip
	afx_msg void OnBnClickedOk();
};
