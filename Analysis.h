#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 
#include <Winsock2.h>
#include "Protocol.h"


/*��·���*/
int Analyze_Frame(const u_char * Packet, DataPacket * data, PacketCount *NumPacket);

/*������*/
int Analyze_Ip(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
int Analyze_Ip6(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
int Analyze_Arp(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);

/*������*/
int Analyze_Icmp(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
//icmp��Ϊ���⣬ͨ����Ϊ����ip��һ���ݣ�����������Ϊip������Ч��
//�ɵ���ʽ�������д��䣬��tcp��udpһ����������������ڴ����������
int Analyze_Icmp6(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);

int Analyze_Tcp(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);
int Analyze_Udp(const u_char * Packet, DataPacket *dtat, PacketCount *NumPacket);

/*Ӧ�ò��*/
//int Analyze_Http(const u_char * Packet, DataPacket *data, PacketCount *NumPacket);

/*�����ݰ���ʮ�����Ƶķ�ʽ��ӡ*/
void Output_Packet(const u_char * Packet, int size_Packet, CString *buf);