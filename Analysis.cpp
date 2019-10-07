#pragma once
#include "stdafx.h"
#include "Analysis.h"
#pragma warning(disable : 4996)

int Analyze_Frame(const u_char * Packet, DataPacket * data, PacketCount * NumPacket)
{
	MacHead *Mac_head = (MacHead *)Packet;
	data->Mac_head = (MacHead *)malloc(sizeof(MacHead));

	if (data->Mac_head == NULL)
	{
		return FALSE;
	}

	for (int i = 0; i < 6; i++)
	{
		data->Mac_head->dest[i] = Mac_head->dest[i];
		data->Mac_head->src[i] = Mac_head->src[i];
	}

	NumPacket->Num_SUM++;
	data->Mac_head->Type = ntohs(Mac_head->Type);

	switch (data->Mac_head->Type)
	{
	case 0x0806:
		return Analyze_Arp((u_char *)Packet + 14, data, NumPacket);

	case 0x0800:
		return Analyze_Ip((u_char *)Packet + 14, data, NumPacket);

	case 0x86dd:
		return Analyze_Ip6((u_char *)Packet + 14, data, NumPacket);

	default:
		NumPacket->Num_OTH++;
		break;
	}

	return TRUE;
}
int Analyze_Arp(const u_char * Packet, DataPacket *data, PacketCount *NumPacket)
{
	ArpHead *Arp_head = (ArpHead *)Packet;
	data->Arp_head = (ArpHead *)malloc(sizeof(ArpHead));

	if (NULL == data->Arp_head)
		return FALSE;

	//复制IP及MAC
	for (int i = 0; i<6; i++)
	{
		if (i<4)
		{
			data->Arp_head->Arp_destip[i] = Arp_head->Arp_destip[i];
			data->Arp_head->Arp_srcip[i] = Arp_head->Arp_srcip[i];
		}
		data->Arp_head->Arp_destmac[i] = Arp_head->Arp_destmac[i];
		data->Arp_head->Arp_srcmac[i] = Arp_head->Arp_srcmac[i];
	}

	data->Arp_head->Arp_hln = Arp_head->Arp_hln;
	data->Arp_head->Arp_hrd = ntohs(Arp_head->Arp_hrd);
	data->Arp_head->Arp_op = ntohs(Arp_head->Arp_op);
	data->Arp_head->Arp_pln = Arp_head->Arp_pln;
	data->Arp_head->Arp_pro = ntohs(Arp_head->Arp_pro);

	strncpy(data->PacketType, "ARP", 8);
	NumPacket->Num_ARP++;

	return TRUE;
}

int Analyze_Ip(const u_char * Packet, DataPacket * data, PacketCount * NumPacket)
{
	IpHead *Ip_head = (IpHead *)Packet;
	data->Ip_head = (IpHead *)malloc(sizeof(IpHead));

	if (NULL == data->Ip_head)
		return FALSE;
	data->Ip_head->check = Ip_head->check;
	NumPacket->Num_IP++;

	/*for(i = 0;i<4;i++)
	{
	data->Ip_head->daddr[i] = Ip_head->daddr[i];
	data->Ip_head->saddr[i] = Ip_head->saddr[i];
	}*/
	data->Ip_head->saddr = Ip_head->saddr;
	data->Ip_head->daddr = Ip_head->daddr;

	data->Ip_head->frag_off = Ip_head->frag_off;
	data->Ip_head->id = Ip_head->id;
	data->Ip_head->proto = Ip_head->proto;
	data->Ip_head->tlen = ntohs(Ip_head->tlen);
	data->Ip_head->tos = Ip_head->tos;
	data->Ip_head->ttl = Ip_head->ttl;
	data->Ip_head->ihl = Ip_head->ihl;
	data->Ip_head->version = Ip_head->version;
	//data->Ip_head->ver_ihl= Ip_head->ver_ihl;
	data->Ip_head->opt = Ip_head->opt;

	int Iplen = Ip_head->ihl * 4;		//ip头长度
	switch (Ip_head->proto)
	{
	case PROTO_ICMP:
		return Analyze_Icmp((u_char*)Ip_head + Iplen, data, NumPacket);
		break;
	case PROTO_TCP:
		return Analyze_Tcp((u_char*)Ip_head + Iplen, data, NumPacket);
		break;
	case PROTO_UDP:
		return Analyze_Udp((u_char*)Ip_head + Iplen, data, NumPacket);
		break;
	default:
		return FALSE;
		break;
	}
	return TRUE;
}

/*分析网络层：IPV6*/
int Analyze_Ip6(const u_char * Packet, DataPacket * data, PacketCount * NumPacket)
{
	Ip6Head *Ip6_head = (Ip6Head *)Packet;
	data->Ip6_head = (Ip6Head * )malloc(sizeof(Ip6Head));

	if (NULL == data->Ip6_head)
		return FALSE;

	NumPacket->Num_IP6++;
	strncpy(data->PacketType, "IPV6", 8);

	data->Ip6_head->version = Ip6_head->version;
	data->Ip6_head->flowtype = Ip6_head->flowtype;
	data->Ip6_head->flowid = Ip6_head->flowid;
	data->Ip6_head->plen = ntohs(Ip6_head->plen);
	data->Ip6_head->nh = Ip6_head->nh;
	data->Ip6_head->hlim = Ip6_head->hlim;


	for (int i = 0; i<16; i++)
	{
		data->Ip6_head->saddr[i] = Ip6_head->saddr[i];
		data->Ip6_head->daddr[i] = Ip6_head->daddr[i];
	}

	switch (Ip6_head->nh)
	{
	case 0x3a:
		return Analyze_Icmp6((u_char*)Ip6_head + 40, data, NumPacket);
		break;
	case 0x06:
		return Analyze_Tcp((u_char*)Ip6_head + 40, data, NumPacket);
		break;
	case 0x11:
		return Analyze_Udp((u_char*)Ip6_head + 40, data, NumPacket);
		break;
	default:
		return FALSE;
		break;
	}
	
	return TRUE;
}

int Analyze_Icmp(const u_char * Packet, DataPacket * data, PacketCount * NumPacket)
{
	IcmpHead *Icmp_head = (IcmpHead *)Packet;
	data->Icmp_head = (IcmpHead *)malloc(sizeof(IcmpHead));

	if (NULL == data->Icmp_head)
		return FALSE;

	strncpy(data->PacketType, "ICMP", 8);
	NumPacket->Num_ICMP++;

	data->Icmp_head->chksum = Icmp_head->chksum;
	data->Icmp_head->code = Icmp_head->code;
	data->Icmp_head->seq = Icmp_head->seq;
	data->Icmp_head->type = Icmp_head->type;

	return TRUE;
}

int Analyze_Icmp6(const u_char * Packet, DataPacket * data, PacketCount * NumPacket)
{
	Icmp6Head* Icmp6_head = (Icmp6Head *)Packet;
	data->Icmp6_head = (Icmp6Head *)malloc(sizeof(Icmp6Head));

	if (NULL == data->Icmp6_head)
		return FALSE;

	strncpy(data->PacketType, "ICMPv6", 8);
	NumPacket->Num_ICMP6++;

	data->Icmp6_head->chksum = Icmp6_head->chksum;
	data->Icmp6_head->code = Icmp6_head->code;
	data->Icmp6_head->seq = Icmp6_head->seq;
	data->Icmp6_head->type = Icmp6_head->type;
	data->Icmp6_head->op_len = Icmp6_head->op_len;
	data->Icmp6_head->op_type = Icmp6_head->op_type;
	for (int i = 0; i<6; i++)
	{
		data->Icmp6_head->op_ethaddr[i] = Icmp6_head->op_ethaddr[i];
	}

	return TRUE;
}

int Analyze_Tcp(const u_char * Packet, DataPacket * data, PacketCount * NumPacket)
{
	TcpHead *Tcp_head = (TcpHead *)Packet;
	data->Tcp_head = (TcpHead *)malloc(sizeof(TcpHead));


	if (NULL == data->Tcp_head)
		return FALSE;

	data->Tcp_head->ack_seq = Tcp_head->ack_seq;
	data->Tcp_head->check = Tcp_head->check;

	data->Tcp_head->doff = Tcp_head->doff;
	data->Tcp_head->res1 = Tcp_head->res1;
	data->Tcp_head->cwr = Tcp_head->cwr;
	data->Tcp_head->ece = Tcp_head->ece;
	data->Tcp_head->urg = Tcp_head->urg;
	data->Tcp_head->ack = Tcp_head->ack;
	data->Tcp_head->psh = Tcp_head->psh;
	data->Tcp_head->rst = Tcp_head->rst;
	data->Tcp_head->syn = Tcp_head->syn;
	data->Tcp_head->fin = Tcp_head->fin;
	//data->Tcp_head->doff_flag = Tcp_head->doff_flag;

	data->Tcp_head->dport = ntohs(Tcp_head->dport);
	data->Tcp_head->seq = Tcp_head->seq;
	data->Tcp_head->sport = ntohs(Tcp_head->sport);
	data->Tcp_head->urg_ptr = Tcp_head->urg_ptr;
	data->Tcp_head->window = Tcp_head->window;
	data->Tcp_head->opt = Tcp_head->opt;

	/////////////////////*不要忘记http分支*/////////////////////////
	if (ntohs(Tcp_head->dport) == 80 || ntohs(Tcp_head->sport) == 80)
	{
		NumPacket->Num_HTTP++;
		strncpy(data->PacketType, "HTTP", 8);
	}
	else
	{
		NumPacket->Num_TCP++;
		strncpy(data->PacketType, "TCP", 8);
	}

	return TRUE;
}


/*分析传输层：UDP*/
int Analyze_Udp(const u_char * Packet, DataPacket * data, PacketCount * NumPacket)
{
	UdpHead *Udp_head = (UdpHead *)Packet;
	data->Udp_head = (UdpHead *)malloc(sizeof(UdpHead));
	if (NULL == data->Udp_head)
		return FALSE;

	data->Udp_head->check = Udp_head->check;
	data->Udp_head->dport = ntohs(Udp_head->dport);
	data->Udp_head->len = ntohs(Udp_head->len);
	data->Udp_head->sport = ntohs(Udp_head->sport);

	strncpy(data->PacketType, "UDP", 8);
	NumPacket->Num_UDP++;

	return TRUE;
}

//将数据包以十六进制方式打印出来
void Output_Packet(const u_char * Packet, int size_Packet, CString *buf)
{
	int RowCount;
	u_char ch;

	char TempBuf[256];
	memset(TempBuf, 0, 256);

	for (int i = 0; i<size_Packet; i += 16)
	{
		buf->AppendFormat(_T("%04x:  "), (u_int)i);
		RowCount = (size_Packet - i) > 16 ? 16 : (size_Packet - i);

		for (int j = 0; j < RowCount; j++)
			buf->AppendFormat(_T("%02x  "), (u_int)Packet[i + j]);

		//不足16，用空格补足
		if (RowCount <16)
			for (int j = RowCount; j<16; j++)
				buf->AppendFormat(_T("    "));

		for (int j = 0; j < RowCount; j++)
		{
			ch = Packet[i + j];
			ch = isprint(ch) ? ch : '.';
			buf->AppendFormat(_T("%c"), ch);
		}

		buf->Append(_T("\r\n"));

		if (RowCount<16)
			return;
	}
}