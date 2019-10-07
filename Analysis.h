#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 
#include <Winsock2.h>
#include "Protocol.h"


/*链路层包*/
int Analyze_Frame(const u_char * Packet, DataPacket * data, PacketCount *NumPacket);

/*网络层包*/
int Analyze_Ip(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
int Analyze_Ip6(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
int Analyze_Arp(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);

/*传输层包*/
int Analyze_Icmp(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
//icmp较为特殊，通常认为它是ip的一部份，但是它是作为ip包的有效载
//荷的形式在网络中传输，如tcp和udp一样，所以这里把它在传输层来处理
int Analyze_Icmp6(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);

int Analyze_Tcp(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
int Analyze_Udp(const u_char * Packet, DataPacket *dtat, PacketCount *NumPacket);

/*应用层包*/
//int Analyze_Http(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);

/*将数据包以十六进制的方式打印*/
void Output_Packet(const u_char * Packet, int size_Packet, CString *buf);