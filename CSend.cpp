// CSend.cpp: 实现文件
//

#include "stdafx.h"
#include "Monitor.h"
#include "CSend.h"
#include "afxdialogex.h"
#include <pcap.h>


// CSend 对话框

IMPLEMENT_DYNAMIC(CSend, CDialogEx)

CSend::CSend(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON3);
}

CSend::~CSend()
{
}

int CSend::StartSend()
{
	pcap_if_t *alldev, *dev;
	char Errbuf[256];
	pcap_findalldevs(&alldev, Errbuf);
	int i;
	pcap_t *devhandle;

	int MaxPacketLen = 100;
	unsigned char *pBuf = (unsigned char *)malloc(MaxPacketLen * sizeof(unsigned char));
	unsigned char data[] = {
		0x58, 0x69, 0x6c, 0x5e, 0x70, 0x24, 0x70, 0x8b, 0xcd, 0x0f, 0x2f, 0x7c, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x48, 0x71, 0x87, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00, 0x0a, 0x12, 0x48, 0xa6, 0x71, 0x8e,
		0x18, 0x11, 0xda, 0xbf, 0x23, 0x3d, 0x00, 0x34, 0xdc, 0x9c, 0x94, 0x03, 0x0b, 0xb9, 0x00, 0x00,
		0x00, 0x2c, 0x01, 0x03, 0x03, 0xf2, 0x00, 0xea, 0x32, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x06, 0xa8, 0xf9, 0x5f, 0xd3, 0x00, 0x00, 0x00, 0x27, 0x0f, 0x00, 0x00,};
	
	memset(pBuf, 0xff, MaxPacketLen);
	memcpy(pBuf, data, 80);

	for (i = 0, dev = alldev; i < 3; dev = dev->next, i++);

	devhandle = pcap_open_live(dev->name,
		65536,
		1,
		1000,
		Errbuf);
	if (devhandle == NULL)
	{
		MessageBox(_T("无法打开接口：" + CString(dev->description)));
		pcap_freealldevs(alldev);
		return -1;
	}
	/*
	填写数据包报协议字段
	*/

	for (i = 0; i < 6; i++)
	{
		pBuf[i] = 0x01;
	}
	//设置源MAC地址为:02:02:02:02:02
	for (i = 6; i < 12; i++)
	{
		pBuf[i] = 0x02;
	}
	//设置协议标识为0X0800
	pBuf[12] = 0x08;
	pBuf[13] = 0x00;

	if (pcap_sendpacket(devhandle, pBuf, MaxPacketLen) == -1)
	{
		MessageBox(_T("发送失败！"));
		pcap_close(devhandle);
		pcap_freealldevs(alldev);
		return -1;
	}

	free(pBuf);
	pcap_close(devhandle);
	pcap_freealldevs(alldev);

	return 0;
}

void CSend::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CSend, CDialogEx)
	ON_BN_CLICKED(IDOK, &CSend::OnBnClickedOk)
END_MESSAGE_MAP()


// CSend 消息处理程序


void CSend::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	if (this->StartSend() < 0)
		MessageBox(_T("数据包发送失败,请重试！"));

	CSend::OnOK();
}
