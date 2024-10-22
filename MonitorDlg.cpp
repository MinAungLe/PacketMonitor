
// MonitorDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "Monitor.h"
#include "MonitorDlg.h"
#include "afxdialogex.h"

#pragma warning(disable : 4996)
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

DWORD WINAPI Monitir_CapThread(LPVOID lpParameter);

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


// CMonitorDlg 对话框

CMonitorDlg::CMonitorDlg(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_MONITOR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON3);
	m_pSend = NULL;
}

CMonitorDlg::~CMonitorDlg()
{
	if (m_pSend != NULL)
	{
		delete m_pSend;
	}
}

/////////////////////////function///////////////////////////////////


//初始化
int CMonitorDlg::Mointer_InitCap()
{
	devCount = 0;
	if (pcap_findalldevs(&alldev, Errbuf) == -1)
		return -1;
	for (dev = alldev; dev; dev = dev->next)
		devCount++;
	return 0;
}

//开始捕获
int CMonitorDlg::Mointer_StartCap()
{
	int DevIndex, RuleIndex, count;
	u_int netmask;
	struct bpf_program fcode;

	Mointer_InitCap();

	//获得接口和过滤器索引
	DevIndex = this->ChoseDEV.GetCurSel();
	RuleIndex = this->ChoseRULE.GetCurSel();

	if (0 == DevIndex || CB_ERR == DevIndex)
	{
		MessageBox(_T("请选择一个合适的网卡接口"));
		return -1;
	}
	if (CB_ERR == RuleIndex)
	{
		MessageBox(_T("过滤器选择错误"));
		return -1;
	}

	/*获得选中的网卡接口*/
	dev = alldev;
	for (count = 0; count < DevIndex - 1; count++)
		dev = dev->next;
	/*
	CString STemp;
	STemp.Format(_T("%d"), DevIndex);
	MessageBox(STemp);
	*/
	if ((DevHandle = pcap_open_live(dev->name,	// 设备名
		65536,									//捕获数据包长度																					
		1,										// 混杂模式 (非0意味着是混杂模式)
		1000,									// 读超时设置
		Errbuf									// 错误信息
	)) == NULL)
	{
		MessageBox(_T("无法打开接口：" + CString(dev->description)));
		pcap_freealldevs(alldev);
		return -1;
	}

	/*检查是否为以太网*/
	if (pcap_datalink(DevHandle) != DLT_EN10MB)
	{
		MessageBox(_T("这不适合于非以太网的网络!"));
		pcap_freealldevs(alldev);
		return -1;
	}

	if (dev->addresses != NULL)
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffffff;

	//编译过滤器
	if (0 == RuleIndex)
	{
		char filter[] = "";
		if (pcap_compile(DevHandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}
	else
	{
		CString str;
		char *filter;
		int len;
		this->ChoseRULE.GetLBText(RuleIndex, str);
		len = str.GetLength() + 1;
		filter = (char*)malloc(len);
		for (int i = 0; i < len; i++)
		{
			filter[i] = (char)str.GetAt(i) + 32;
		}
		if (pcap_compile(DevHandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			free(filter);
			return -1;
		}
	}


	//设置过滤器
	if (pcap_setfilter(DevHandle, &fcode) < 0)
	{
		MessageBox(_T("设置过滤器错误"));
		pcap_freealldevs(alldev);
		return -1;
	}

	/* 设置数据包存储路径*/
	CFileFind file;
	char thistime[30];
	struct tm *LocalTime;
	memset(FilePath, 0, 512);
	memset(FileName, 0, 64);

	if (!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"), NULL);
	}

	time_t nowtime;
	time(&nowtime);
	LocalTime = localtime(&nowtime);
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", LocalTime);
	strcpy(FilePath, "SavedData\\");
	strcat(FileName, thistime);
	strcat(FileName, ".pkt");

	strcat(FilePath, FileName);
	DumpFile = pcap_dump_open(DevHandle, FilePath);
	if (DumpFile == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		pcap_freealldevs(alldev);
		return -1;
	}

	pcap_freealldevs(alldev);

	/*接收数据，新建线程处理*/
	LPDWORD threadCap = NULL;
	ThreadHandle = CreateThread(NULL, 0, Monitir_CapThread, this, 0, threadCap);
	if (ThreadHandle == NULL)
	{
		int code = GetLastError();
		CString str;
		str.Format(_T("创建线程错误，代码为%d."), code);
		MessageBox(str);
		return -1;
	}

	return 1;
}

DWORD WINAPI Monitir_CapThread(LPVOID lpParameter)
{
	int res, nItem;
	struct tm *LocalTime;
	CString TimeStr, Buffer, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *PacketHeader;						//数据包头
	const u_char *PacketData = NULL, *pData = NULL;			//网络中收到的字节流数据
	u_char *ppkt_data;

	CMonitorDlg *Pthis = (CMonitorDlg *)lpParameter;
	if (NULL == Pthis->ThreadHandle)
	{
		MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
		return -1;
	}

	while ((res = pcap_next_ex(Pthis->DevHandle, &PacketHeader, &PacketData)) >= 0)
	{
		if (res == 0)				//超时
			continue;

		DataPacket *data = (DataPacket *)malloc(sizeof(DataPacket));
		memset(data, 0, sizeof(DataPacket));

		if (NULL == data)
		{
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (Analyze_Frame(PacketData, data, &(Pthis->Packet_count)) < 0)
			continue;

		//将数据包保存到打开的文件中
		if (Pthis->DumpFile != NULL)
		{
			pcap_dump((unsigned char*)Pthis->DumpFile, PacketHeader, PacketData);
		}

		//更新各类数据包计数
		Pthis->Mointer_UpdateCountPacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(PacketHeader->len);
		memcpy(ppkt_data, PacketData, PacketHeader->len);

		Pthis->LocalDataList.AddTail(data);
		Pthis->NetlDataList.AddTail(ppkt_data);

		/*预处理，获得时间、长度*/
		data->Length = PacketHeader->len;								//链路中收到的数据长度
		local_tv_sec = PacketHeader->ts.tv_sec;
		LocalTime = localtime(&local_tv_sec);
		data->Time[0] = LocalTime->tm_year + 1900;
		data->Time[1] = LocalTime->tm_mon + 1;
		data->Time[2] = LocalTime->tm_mday;
		data->Time[3] = LocalTime->tm_hour;
		data->Time[4] = LocalTime->tm_min;
		data->Time[5] = LocalTime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		Buffer.Format(_T("%d"), Pthis->NumPacket);
		nItem = Pthis->PackListCtrl.InsertItem(Pthis->NumPacket, Buffer);

		/*显示时间戳*/
		TimeStr.Format(_T("%d/%d/%d  %d:%d:%d"), data->Time[0],
			data->Time[1], data->Time[2], data->Time[3], data->Time[4], data->Time[5]);
		Pthis->PackListCtrl.SetItemText(nItem, 1, TimeStr);
		//Pthis->PackListCtrl.setitem

		/*显示长度*/
		Buffer.Empty();
		Buffer.Format(_T("%d"), data->Length);
		Pthis->PackListCtrl.SetItemText(nItem, 2, Buffer);

		/*显示源MAC*/
		Buffer.Empty();
		Buffer.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->Mac_head->src[0], data->Mac_head->src[1],
			data->Mac_head->src[2], data->Mac_head->src[3], data->Mac_head->src[4], data->Mac_head->src[5]);
		Pthis->PackListCtrl.SetItemText(nItem, 3, Buffer);

		/*显示目的MAC*/
		Buffer.Empty();
		Buffer.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->Mac_head->dest[0], data->Mac_head->dest[1],
			data->Mac_head->dest[2], data->Mac_head->dest[3], data->Mac_head->dest[4], data->Mac_head->dest[5]);
		Pthis->PackListCtrl.SetItemText(nItem, 4, Buffer);

		/*获得协议*/
		Pthis->PackListCtrl.SetItemText(nItem, 5, CString(data->PacketType));

		/*获得源IP*/
		Buffer.Empty();
		if (0x0806 == data->Mac_head->Type)
		{
			Buffer.Format(_T("%d.%d.%d.%d"),
				data->Arp_head->Arp_srcip[0],
				data->Arp_head->Arp_srcip[1],
				data->Arp_head->Arp_srcip[2],
				data->Arp_head->Arp_srcip[3]);
		}
		else if (0x0800 == data->Mac_head->Type) {
			struct  in_addr in;
			in.S_un.S_addr = data->Ip_head->saddr;
			Buffer = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->Mac_head->Type) {
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					Buffer.AppendFormat(_T("%02x:"), data->Ip6_head->saddr[n]);
				else
					Buffer.AppendFormat(_T("%02x"), data->Ip6_head->saddr[n]);
			}
		}
		Pthis->PackListCtrl.SetItemText(nItem, 6, Buffer);

		/*获得目的IP*/
		Buffer.Empty();
		if (0x0806 == data->Mac_head->Type)
		{
			Buffer.Format(_T("%d.%d.%d.%d"), data->Arp_head->Arp_destip[0],
				data->Arp_head->Arp_destip[1], data->Arp_head->Arp_destip[2], data->Arp_head->Arp_destip[3]);
		}
		else if (0x0800 == data->Mac_head->Type)
		{
			struct  in_addr in;
			in.S_un.S_addr = data->Ip_head->daddr;
			Buffer = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->Mac_head->Type)
		{
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					Buffer.AppendFormat(_T("%02x:"), data->Ip6_head->daddr[n]);
				else
					Buffer.AppendFormat(_T("%02x"), data->Ip6_head->daddr[n]);
			}
		}
		Pthis->PackListCtrl.SetItemText(nItem, 7, Buffer);

		/*对包计数*/
		Pthis->NumPacket++;

	}
	return 1;
}

int CMonitorDlg::Mointer_UpdateTree(int index)
{
	POSITION LocalPos;
	CString str;
	int i;

	this->PackTreeCtrl.DeleteAllItems();

	LocalPos = this->LocalDataList.FindIndex(index);
	DataPacket* Local_data = (DataPacket*)(this->LocalDataList.GetAt(LocalPos));

	HTREEITEM root = this->PackTreeCtrl.GetRootItem();
	str.Format(_T("接收到的第%d个数据包"), index + 1);
	HTREEITEM data = this->PackTreeCtrl.InsertItem(str, root);

	/*处理帧数据*/
	HTREEITEM frame = this->PackTreeCtrl.InsertItem(_T("链路层数据"), data);
	//源MAC
	str.Format(_T("源MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), Local_data->Mac_head->src[i]);
		else
			str.AppendFormat(_T("%02x"), Local_data->Mac_head->src[i]);
	}
	this->PackTreeCtrl.InsertItem(str, frame);
	//目的MAC
	str.Format(_T("目的MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), Local_data->Mac_head->dest[i]);
		else
			str.AppendFormat(_T("%02x"), Local_data->Mac_head->dest[i]);
	}
	this->PackTreeCtrl.InsertItem(str, frame);
	//类型
	str.Format(_T("类型：0x%02x"), Local_data->Mac_head->Type);
	this->PackTreeCtrl.InsertItem(str, frame);

	/*处理IP、ARP、IPv6数据包*/
	if (0x0806 == Local_data->Mac_head->Type)							//ARP
	{
		HTREEITEM arp = this->PackTreeCtrl.InsertItem(_T("ARP协议头"), data);
		str.Format(_T("硬件类型：%d"), Local_data->Arp_head->Arp_hrd);
		this->PackTreeCtrl.InsertItem(str, arp);
		str.Format(_T("协议类型：0x%02x"), Local_data->Arp_head->Arp_pro);
		this->PackTreeCtrl.InsertItem(str, arp);
		str.Format(_T("硬件地址长度：%d"), Local_data->Arp_head->Arp_hln);
		this->PackTreeCtrl.InsertItem(str, arp);
		str.Format(_T("协议地址长度：%d"), Local_data->Arp_head->Arp_pln);
		this->PackTreeCtrl.InsertItem(str, arp);
		str.Format(_T("操作码：%d"), Local_data->Arp_head->Arp_op);
		this->PackTreeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方MAC："));
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), Local_data->Arp_head->Arp_srcmac[i]);
			else
				str.AppendFormat(_T("%02x"), Local_data->Arp_head->Arp_srcmac[i]);
		}
		this->PackTreeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方IP："), Local_data->Arp_head->Arp_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), Local_data->Arp_head->Arp_srcip[i]);
			else
				str.AppendFormat(_T("%d"), Local_data->Arp_head->Arp_srcip[i]);
		}
		this->PackTreeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方MAC："), Local_data->Arp_head->Arp_hln);
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), Local_data->Arp_head->Arp_destmac[i]);
			else
				str.AppendFormat(_T("%02x"), Local_data->Arp_head->Arp_destmac[i]);
		}
		this->PackTreeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方IP："), Local_data->Arp_head->Arp_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), Local_data->Arp_head->Arp_destip[i]);
			else
				str.AppendFormat(_T("%d"), Local_data->Arp_head->Arp_destip[i]);
		}
		this->PackTreeCtrl.InsertItem(str, arp);

	}
	else if (0x0800 == Local_data->Mac_head->Type)//IP
	{

		HTREEITEM ip = this->PackTreeCtrl.InsertItem(_T("IP协议头"), data);

		str.Format(_T("版本：%d"), Local_data->Ip_head->version);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("IP头长：%d"), Local_data->Ip_head->ihl * 4);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("服务类型：%d"), Local_data->Ip_head->tos);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("总长度：%d"), Local_data->Ip_head->tlen);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("标识：0x%02x"), Local_data->Ip_head->id);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("段偏移：%d"), Local_data->Ip_head->frag_off);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("生存期：%d"), Local_data->Ip_head->ttl);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("协议：%d"), Local_data->Ip_head->proto);
		this->PackTreeCtrl.InsertItem(str, ip);
		str.Format(_T("头部校验和：0x%02x"), Local_data->Ip_head->check);
		this->PackTreeCtrl.InsertItem(str, ip);

		str.Format(_T("源IP："));
		struct in_addr in;
		in.S_un.S_addr = Local_data->Ip_head->saddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->PackTreeCtrl.InsertItem(str, ip);

		str.Format(_T("目的IP："));
		in.S_un.S_addr = Local_data->Ip_head->daddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->PackTreeCtrl.InsertItem(str, ip);

		/*处理传输层ICMP、UDP、TCP*/
		if (1 == Local_data->Ip_head->proto)							//ICMP
		{
			HTREEITEM icmp = this->PackTreeCtrl.InsertItem(_T("ICMP协议头"), data);

			str.Format(_T("类型:%d"), Local_data->Icmp_head->type);
			this->PackTreeCtrl.InsertItem(str, icmp);
			str.Format(_T("代码:%d"), Local_data->Icmp_head->code);
			this->PackTreeCtrl.InsertItem(str, icmp);
			str.Format(_T("序号:%d"), Local_data->Icmp_head->seq);
			this->PackTreeCtrl.InsertItem(str, icmp);
			str.Format(_T("校验和:%d"), Local_data->Icmp_head->chksum);
			this->PackTreeCtrl.InsertItem(str, icmp);

		}
		else if (6 == Local_data->Ip_head->proto) {				//TCP

			HTREEITEM tcp = this->PackTreeCtrl.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), Local_data->Tcp_head->sport);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), Local_data->Tcp_head->dport);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), Local_data->Tcp_head->seq);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), Local_data->Tcp_head->ack_seq);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), Local_data->Tcp_head->doff);

			HTREEITEM flag = this->PackTreeCtrl.InsertItem(_T(" +标志位"), tcp);

			str.Format(_T("cwr %d"), Local_data->Tcp_head->cwr);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("ece %d"), Local_data->Tcp_head->ece);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("urg %d"), Local_data->Tcp_head->urg);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("ack %d"), Local_data->Tcp_head->ack);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("psh %d"), Local_data->Tcp_head->psh);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("rst %d"), Local_data->Tcp_head->rst);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("syn %d"), Local_data->Tcp_head->syn);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("fin %d"), Local_data->Tcp_head->fin);
			this->PackTreeCtrl.InsertItem(str, flag);

			str.Format(_T("  紧急指针:%d"), Local_data->Tcp_head->urg_ptr);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%02x"), Local_data->Tcp_head->check);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), Local_data->Tcp_head->opt);
			this->PackTreeCtrl.InsertItem(str, tcp);
		}
		else if (17 == Local_data->Ip_head->proto) {				//UDP
			HTREEITEM udp = this->PackTreeCtrl.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), Local_data->Udp_head->sport);
			this->PackTreeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), Local_data->Udp_head->dport);
			this->PackTreeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), Local_data->Udp_head->len);
			this->PackTreeCtrl.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), Local_data->Udp_head->check);
			this->PackTreeCtrl.InsertItem(str, udp);
		}
	}
	else if (0x86dd == Local_data->Mac_head->Type) {		//IPv6
		HTREEITEM ip6 = this->PackTreeCtrl.InsertItem(_T("IPv6协议头"), data);

		//////////////////////////////////////////////////////////////////////////////////////////
		str.Format(_T("版本:%d"), Local_data->Ip6_head->flowtype);
		this->PackTreeCtrl.InsertItem(str, ip6);
		str.Format(_T("流类型:%d"), Local_data->Ip6_head->version);
		this->PackTreeCtrl.InsertItem(str, ip6);
		///////////////////////////////////////////////////////////////////////////////////////////
		str.Format(_T("流标签:%d"), Local_data->Ip6_head->flowid);
		this->PackTreeCtrl.InsertItem(str, ip6);
		str.Format(_T("有效载荷长度:%d"), Local_data->Ip6_head->plen);
		this->PackTreeCtrl.InsertItem(str, ip6);
		str.Format(_T("下一个首部:0x%02x"), Local_data->Ip6_head->nh);
		this->PackTreeCtrl.InsertItem(str, ip6);
		str.Format(_T("跳限制:%d"), Local_data->Ip6_head->hlim);
		this->PackTreeCtrl.InsertItem(str, ip6);

		str.Format(_T("源地址:"));
		int n;
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), Local_data->Ip6_head->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), Local_data->Ip6_head->saddr[n]);
		}
		this->PackTreeCtrl.InsertItem(str, ip6);

		str.Format(_T("目的地址:"));
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), Local_data->Ip6_head->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), Local_data->Ip6_head->saddr[n]);
		}
		this->PackTreeCtrl.InsertItem(str, ip6);

		/*处理传输层ICMPv6、UDP、TCP*/
		if (0x3a == Local_data->Ip6_head->nh)							//ICMPv6
		{
			HTREEITEM icmp6 = this->PackTreeCtrl.InsertItem(_T("ICMPv6协议头"), data);

			str.Format(_T("类型:%d"), Local_data->Icmp6_head->type);
			this->PackTreeCtrl.InsertItem(str, icmp6);
			str.Format(_T("代码:%d"), Local_data->Icmp6_head->code);
			this->PackTreeCtrl.InsertItem(str, icmp6);
			str.Format(_T("序号:%d"), Local_data->Icmp6_head->seq);
			this->PackTreeCtrl.InsertItem(str, icmp6);
			str.Format(_T("校验和:%d"), Local_data->Icmp6_head->chksum);
			this->PackTreeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-类型:%d"), Local_data->Icmp6_head->op_type);
			this->PackTreeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-长度%d"), Local_data->Icmp6_head->op_len);
			this->PackTreeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-链路层地址:"));
			int i;
			for (i = 0; i < 6; i++)
			{
				if (i <= 4)
					str.AppendFormat(_T("%02x-"), Local_data->Icmp6_head->op_ethaddr[i]);
				else
					str.AppendFormat(_T("%02x"), Local_data->Icmp6_head->op_ethaddr[i]);
			}
			this->PackTreeCtrl.InsertItem(str, icmp6);

		}
		else if (0x06 == Local_data->Ip6_head->nh) {				//TCP

			HTREEITEM tcp = this->PackTreeCtrl.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), Local_data->Tcp_head->sport);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), Local_data->Tcp_head->dport);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), Local_data->Tcp_head->seq);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), Local_data->Tcp_head->ack_seq);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), Local_data->Tcp_head->doff);

			HTREEITEM flag = this->PackTreeCtrl.InsertItem(_T("标志位"), tcp);

			str.Format(_T("cwr %d"), Local_data->Tcp_head->cwr);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("ece %d"), Local_data->Tcp_head->ece);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("urg %d"), Local_data->Tcp_head->urg);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("ack %d"), Local_data->Tcp_head->ack);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("psh %d"), Local_data->Tcp_head->psh);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("rst %d"), Local_data->Tcp_head->rst);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("syn %d"), Local_data->Tcp_head->syn);
			this->PackTreeCtrl.InsertItem(str, flag);
			str.Format(_T("fin %d"), Local_data->Tcp_head->fin);
			this->PackTreeCtrl.InsertItem(str, flag);

			str.Format(_T("  紧急指针:%d"), Local_data->Tcp_head->urg_ptr);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%02x"), Local_data->Tcp_head->check);
			this->PackTreeCtrl.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), Local_data->Tcp_head->opt);
			this->PackTreeCtrl.InsertItem(str, tcp);
		}
		else if (0x11 == Local_data->Ip6_head->nh) {				//UDP
			HTREEITEM udp = this->PackTreeCtrl.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), Local_data->Udp_head->sport);
			this->PackTreeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), Local_data->Udp_head->dport);
			this->PackTreeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), Local_data->Udp_head->len);
			this->PackTreeCtrl.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), Local_data->Udp_head->check);
			this->PackTreeCtrl.InsertItem(str, udp);
		}
	}

	return 1;
}

int CMonitorDlg::Mointer_UpdateEdit(int index)
{
	POSITION localpos, netpos;
	localpos = this->LocalDataList.FindIndex(index);
	netpos = this->NetlDataList.FindIndex(index);

	DataPacket* local_data = (DataPacket*)(this->LocalDataList.GetAt(localpos));
	u_char * net_data = (u_char*)(this->NetlDataList.GetAt(netpos));

	CString buf;
	Output_Packet(net_data, local_data->Length, &buf);

	this->PackEdit.SetWindowText(buf);

	return 1;
}

int CMonitorDlg::Mointer_UpdateCountPacket()
{
	CString StrNum;
	StrNum.Format(_T("%d"), this->Packet_count.Num_ARP);
	this->ARPEdit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_HTTP);
	this->HTTPEdit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_ICMP);
	this->ICMPEdit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_IP6);
	this->IPV6Edit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_OTH);
	this->OTHEdit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_TCP);
	this->TCPEdit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_UDP);
	this->UDPEdit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_IP);
	this->IPV4Edit.SetWindowText(StrNum);

	StrNum.Format(_T("%d"), this->Packet_count.Num_IP6);
	this->ICMPV6Edit.SetWindowText(StrNum);

	return 1;
}

int CMonitorDlg::Mointer_SaveFile()
{
	CFileFind Find;
	if (NULL == Find.FindFile(CString(FilePath)))
	{
		MessageBox(_T("保存文件遇到未知意外"));
		return -1;
	}

	//打开文件对话框
	CFileDialog   FileDlg(FALSE, _T(".pkt"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)
	{
		CopyFile(CString(FilePath), FileDlg.GetPathName(), TRUE);
	}

	return 1;
}

int CMonitorDlg::Mointer_ReadFile(CString path)
{
	int res, nItem, i;
	struct tm *LocalTime;
	CString TimeStr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *PacketHeader;									  //数据包头
	const u_char *pkt_data = NULL;     //网络中收到的字节流数据
	u_char *ppkt_data;

	CMonitorDlg *Pthis = this;						//些代码改造自lixsinff_CapThread，为节约工作量，故保留Pthis指针
	pcap_t *fp;

	//首先处理一下路径，利用pcap_open_offline打开文件时，
	//路径需要用char *类型，不能用CString强制转换后的char *
	int len = path.GetLength() + 1;							/////////////////////////////////注意这一个细节，必须要加1，否则会出错
	char* charpath = (char *)malloc(len);
	memset(charpath, 0, len);
	if (NULL == charpath)
		return -1;

	for (i = 0; i < len; i++)
		charpath[i] = (char)path.GetAt(i);

	//打开相关文件
	if ((fp = pcap_open_offline( /*(char*)(LPCTSTR)path*/charpath, Errbuf)) == NULL)
	{
		MessageBox(_T("打开文件错误") + CString(Errbuf));
		return -1;
	}

	while ((res = pcap_next_ex(fp, &PacketHeader, &pkt_data)) >= 0)
	{
		DataPacket *data = (DataPacket*)malloc(sizeof(DataPacket));
		memset(data, 0, sizeof(DataPacket));

		if (NULL == data)
		{
			MessageBox(_T("空间已满，无法接收新的数据包"));
			return  -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (Analyze_Frame(pkt_data, data, &(Pthis->Packet_count)) < 0)
			continue;

		//更新各类数据包计数
		Pthis->Mointer_UpdateCountPacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(PacketHeader->len);
		memcpy(ppkt_data, pkt_data, PacketHeader->len);

		Pthis->LocalDataList.AddTail(data);
		Pthis->NetlDataList.AddTail(ppkt_data);

		/*预处理，获得时间、长度*/
		data->Length = PacketHeader->len;								//链路中收到的数据长度
		local_tv_sec = PacketHeader->ts.tv_sec;
		LocalTime = localtime(&local_tv_sec);
		data->Time[0] = LocalTime->tm_year + 1900;
		data->Time[1] = LocalTime->tm_mon + 1;
		data->Time[2] = LocalTime->tm_mday;
		data->Time[3] = LocalTime->tm_hour;
		data->Time[4] = LocalTime->tm_min;
		data->Time[5] = LocalTime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"), Pthis->NumPacket);
		nItem = Pthis->PackListCtrl.InsertItem(Pthis->NumPacket, buf);

		/*显示时间戳*/
		TimeStr.Format(_T("%d/%d/%d  %d:%d:%d"),
			data->Time[0],
			data->Time[1], 
			data->Time[2], 
			data->Time[3],
			data->Time[4],
			data->Time[5]);
		Pthis->PackListCtrl.SetItemText(nItem, 1, TimeStr);

		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"), data->Length);
		Pthis->PackListCtrl.SetItemText(nItem, 2, buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),
			data->Mac_head->src[0],
			data->Mac_head->src[1],
			data->Mac_head->src[2],
			data->Mac_head->src[3],
			data->Mac_head->src[4],
			data->Mac_head->src[5]);
		Pthis->PackListCtrl.SetItemText(nItem, 3, buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),
			data->Mac_head->dest[0], 
			data->Mac_head->dest[1],
			data->Mac_head->dest[2],
			data->Mac_head->dest[3],
			data->Mac_head->dest[4],
			data->Mac_head->dest[5]);
		Pthis->PackListCtrl.SetItemText(nItem, 4, buf);

		/*获得协议*/
		Pthis->PackListCtrl.SetItemText(nItem, 5, CString(data->PacketType));

		/*获得源IP*/
		buf.Empty();
		if (0x0806 == data->Mac_head->Type)
		{
			buf.Format(_T("%d.%d.%d.%d"),
				data->Arp_head->Arp_srcip[0],
				data->Arp_head->Arp_srcip[1],
				data->Arp_head->Arp_srcip[2],
				data->Arp_head->Arp_srcip[3]);
		}
		else  if (0x0800 == data->Mac_head->Type) {
			struct  in_addr in;
			in.S_un.S_addr = data->Ip_head->saddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->Mac_head->Type) {
			int i;
			for (i = 0; i < 8; i++)
			{
				if (i <= 6)
					buf.AppendFormat(_T("%02x-"), data->Ip6_head->saddr[i]);
				else
					buf.AppendFormat(_T("%02x"), data->Ip6_head->saddr[i]);
			}
		}
		Pthis->PackListCtrl.SetItemText(nItem, 6, buf);

		/*获得目的IP*/
		buf.Empty();
		if (0x0806 == data->Mac_head->Type)
		{
			buf.Format(_T("%d.%d.%d.%d"),
				data->Arp_head->Arp_destip[0],
				data->Arp_head->Arp_destip[1],
				data->Arp_head->Arp_destip[2],
				data->Arp_head->Arp_destip[3]);
		}
		else if (0x0800 == data->Mac_head->Type) {
			struct  in_addr in;
			in.S_un.S_addr = data->Ip_head->daddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->Mac_head->Type) {
			int i;
			for (i = 0; i < 8; i++)
			{
				if (i <= 6)

					buf.AppendFormat(_T("%02x-"), data->Ip6_head->daddr[i]);
				else
					buf.AppendFormat(_T("%02x"), data->Ip6_head->daddr[i]);
			}
		}
		Pthis->PackListCtrl.SetItemText(nItem, 7, buf);

		/*对包计数*/
		Pthis->NumPacket++;
	}

	pcap_close(fp);

	return 1;
}

void CMonitorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_DEV, ChoseDEV);
	DDX_Control(pDX, IDC_COMBO_RULE, ChoseRULE);
	DDX_Control(pDX, IDC_LIST1, PackListCtrl);
	DDX_Control(pDX, IDC_TREE1, PackTreeCtrl);
	DDX_Control(pDX, IDC_EDIT1, PackEdit);
	DDX_Control(pDX, IDC_EDIT2, TCPEdit);
	DDX_Control(pDX, IDC_EDIT3, HTTPEdit);
	DDX_Control(pDX, IDC_EDIT4, IPV6Edit);
	DDX_Control(pDX, IDC_EDIT5, UDPEdit);
	DDX_Control(pDX, IDC_EDIT6, ARPEdit);
	DDX_Control(pDX, IDC_EDIT7, IPV4Edit);
	DDX_Control(pDX, IDC_EDIT8, ICMPEdit);
	DDX_Control(pDX, IDC_EDIT9, ICMPV6Edit);
	DDX_Control(pDX, IDC_EDIT10, OTHEdit);
	DDX_Control(pDX, IDC_BUTTON_START, BTStart);
	DDX_Control(pDX, IDC_BUTTON_STOP, BTStop);
	DDX_Control(pDX, IDC_BUTTON_SAVE, BTSave);
	DDX_Control(pDX, IDC_BUTTON_READ, BTRead);
}

BEGIN_MESSAGE_MAP(CMonitorDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_START, &CMonitorDlg::OnBnClickedButtonStart)
	ON_BN_CLICKED(IDC_BUTTON_STOP, &CMonitorDlg::OnBnClickedButtonStop)
	ON_BN_CLICKED(IDC_BUTTON_SAVE, &CMonitorDlg::OnBnClickedButtonSave)
	ON_BN_CLICKED(IDC_BUTTON_READ, &CMonitorDlg::OnBnClickedButtonRead)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CMonitorDlg::OnLvnItemchangedList1)
//	ON_NOTIFY(NM_CUSTOMDRAW, IDC_TREE1, &CMonitorDlg::OnNMCustomdrawTree1)
ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CMonitorDlg::OnNMCustomdrawList1)
ON_BN_CLICKED(IDC_BUTTON1, &CMonitorDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CMonitorDlg 消息处理程序

BOOL CMonitorDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
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
	PackListCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	PackListCtrl.InsertColumn(0, _T("编号"), LVCFMT_JUSTIFYMASK, 60);
	PackListCtrl.InsertColumn(1, _T("时间"), LVCFMT_JUSTIFYMASK, 130);
	PackListCtrl.InsertColumn(2, _T("长度"), LVCFMT_JUSTIFYMASK, 72);
	PackListCtrl.InsertColumn(3, _T("源MAC地址"), LVCFMT_JUSTIFYMASK, 170);
	PackListCtrl.InsertColumn(4, _T("目的MAC地址"), LVCFMT_JUSTIFYMASK, 170);
	PackListCtrl.InsertColumn(5, _T("协议"), LVCFMT_JUSTIFYMASK, 70);
	PackListCtrl.InsertColumn(6, _T("源IP地址"), LVCFMT_JUSTIFYMASK, 170);
	PackListCtrl.InsertColumn(7, _T("目的IP地址"), LVCFMT_JUSTIFYMASK, 170);

	ChoseDEV.AddString(_T("请选择一个网卡接口(必选)"));
	ChoseRULE.AddString(_T("请选择过滤规则(可选)"));

	if (Mointer_InitCap()<0)
		return FALSE;

	/*初始化接口列表*/
	for (dev = alldev; dev; dev = dev->next)
	{
		if (dev->description)
			ChoseDEV.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题
	}

	/*初始化过滤规则列表*/
	ChoseRULE.AddString(_T("TCP"));
	ChoseRULE.AddString(_T("UDP"));
	ChoseRULE.AddString(_T("IP"));
	ChoseRULE.AddString(_T("ICMP"));
	ChoseRULE.AddString(_T("ARP"));

	ChoseDEV.SetCurSel(0);
	ChoseRULE.SetCurSel(0);

	BTStop.EnableWindow(FALSE);
	BTSave.EnableWindow(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMonitorDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMonitorDlg::OnPaint()
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
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标显示
HCURSOR CMonitorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMonitorDlg::OnBnClickedButtonStart()
{
	// TODO: 在此添加控件通知处理程序代码
	//如果已经有数据了，提示保存数据
	if (this->LocalDataList.IsEmpty() == FALSE)
	{
		if (MessageBox(_T("确认不保存数据？"), _T("警告"), MB_YESNO) == IDNO)
		{
			this->Mointer_SaveFile();
		}
	}

	this->NumPacket = 1;							//重新计数
	this->LocalDataList.RemoveAll();				//每次一开始就将以前存的数据清空掉
	this->NetlDataList.RemoveAll();
	memset(&(this->Packet_count), 0, sizeof(PacketCount));
	this->Mointer_UpdateCountPacket();

	if (this->Mointer_StartCap()<0)
		return;
	this->PackListCtrl.DeleteAllItems();
	this->PackTreeCtrl.DeleteAllItems();
	this->PackEdit.SetWindowTextW(_T(""));
	this->BTStart.EnableWindow(FALSE);
	this->BTStop.EnableWindow(TRUE);
	this->BTSave.EnableWindow(FALSE);

}


void CMonitorDlg::OnBnClickedButtonStop()
{
	// TODO: 在此添加控件通知处理程序代码
	if (NULL == this->ThreadHandle)
		return;
	if (TerminateThread(this->ThreadHandle, -1) == 0)
	{
		MessageBox(_T("关闭线程错误，请稍后重试"));
		return;
	}
	this->ThreadHandle = NULL;
	this->BTStart.EnableWindow(TRUE);
	this->BTStop.EnableWindow(FALSE);
	this->BTSave.EnableWindow(TRUE);
}


void CMonitorDlg::OnBnClickedButtonSave()
{
	// TODO: 在此添加控件通知处理程序代码
	if (this->Mointer_SaveFile()<0)
		return;
}


void CMonitorDlg::OnBnClickedButtonRead()
{
	// TODO: 在此添加控件通知处理程序代码
	//读取之前将ListCtrl清空
	this->PackListCtrl.DeleteAllItems();
	this->NumPacket = 1;										//列表重新计数
	this->LocalDataList.RemoveAll();							//每次一开始就将以前存的数据清空掉
	this->NetlDataList.RemoveAll();
	memset(&(this->Packet_count), 0, sizeof(PacketCount));		//各类包计数清空

	//打开文件对话框
	CFileDialog   FileDlg(TRUE, _T(".lix"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)
	{
		int ret = this->Mointer_ReadFile(FileDlg.GetPathName());
		if (ret < 0)
			return;
	}
}


void CMonitorDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	int Index;
	Index= this->PackListCtrl.GetHotItem();

	if (Index>this->LocalDataList.GetCount() - 1)
		return;

	this->Mointer_UpdateEdit(Index);
	this->Mointer_UpdateTree(Index);
}

void CMonitorDlg::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	//LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) {
		COLORREF crText;
		char buf[8];
		memset(buf, 0, 8);
		POSITION pos = this->LocalDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
		DataPacket *local_data = (DataPacket *)this->LocalDataList.GetAt(pos);
		strcpy(buf, local_data->PacketType);

		if (strcmp(buf, "IPV6") == 0)
			crText = RGB(111, 224, 254);
		else if (strcmp(buf, "UDP") == 0)
			crText = RGB(194, 195, 252);
		else if (strcmp(buf, "TCP") == 0)
			crText = RGB(230, 230, 230);
		else if (strcmp(buf, "ARP") == 0)
			crText = RGB(226, 238, 227);
		else if (strcmp(buf, "ICMP") == 0)
			crText = RGB(49, 164, 238);
		else if (strcmp(buf, "HTTP") == 0)
			crText = RGB(238, 232, 180);
		else if (strcmp(buf, "ICMPv6") == 0)
			crText = RGB(189, 254, 76);

		pNMCD->clrTextBk = crText;
		*pResult = CDRF_DODEFAULT;
	}
}


void CMonitorDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	if (m_pSend == NULL)
	{
		m_pSend = new CSend();
		m_pSend->Create(IDD_SEND_DIALOG, this);
	}
	m_pSend->ShowWindow(SW_SHOW);
}
