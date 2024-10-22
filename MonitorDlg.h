
// MonitorDlg.h: 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include <pcap.h>
#include "Protocol.h"
#include "Analysis.h"
#include "CSend.h"

// CMonitorDlg 对话框
class CMonitorDlg : public CDialog
{
// 构造
public:
	CMonitorDlg(CWnd* pParent = NULL);	// 标准构造函数
	~CMonitorDlg();

	int Mointer_InitCap();
	int Mointer_StartCap();
	int Mointer_UpdateTree(int index);
	int Mointer_UpdateEdit(int index);
	int Mointer_UpdateCountPacket();
	int Mointer_SaveFile();
	int Mointer_ReadFile(CString path);

	int devCount;								//网卡数量
	PacketCount Packet_count;					//各类数据包计数
	char Errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;
	pcap_if_t *dev;
	pcap_t *DevHandle;
	pcap_dumper_t *DumpFile;
	char FilePath[512];							//	文件保存路径
	char FileName[64];							//	文件名称							

	HANDLE ThreadHandle;


// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MONITOR_DIALOG };
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
	int NumPacket;

	CPtrList LocalDataList;		//保存被本地化后的数据包
	CPtrList NetlDataList;		//保存从网络中直接获取的数据包

	CComboBox ChoseDEV;
	CComboBox ChoseRULE;
	afx_msg void OnBnClickedButtonStart();
	afx_msg void OnBnClickedButtonStop();
	afx_msg void OnBnClickedButtonSave();
	afx_msg void OnBnClickedButtonRead();
	CListCtrl PackListCtrl;
	CTreeCtrl PackTreeCtrl;
	CEdit PackEdit;
	CEdit TCPEdit;
	CEdit HTTPEdit;
	CEdit IPV6Edit;
	CEdit UDPEdit;
	CEdit ARPEdit;
	CEdit IPV4Edit;
	CEdit ICMPEdit;
	CEdit ICMPV6Edit;
	CEdit OTHEdit;

	CButton BTStart;
	CButton BTStop;
	CButton BTSave;
	CButton BTRead;
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
//	afx_msg void OnNMCustomdrawTree1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton1();

private:
	CSend * m_pSend;
};
