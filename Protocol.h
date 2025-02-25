#pragma once
#define PROTO_ICMP 1
#define PROTO_TCP 6					
#define PROTO_UDP 17					 
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321


//Mac帧头 占14个字节
typedef struct _MacHead
{
	u_char		dest[6];		//6个字节 目标地址
	u_char		src[6];			//6个字节 源地址
	u_short		Type;			//2个字节 类型
} MacHead;

//ARP头
typedef struct _ArpHead
{
	u_short		Arp_hrd;			//硬件类型
	u_short		Arp_pro;			//协议类型
	u_char		Arp_hln;			//硬件地址长度
	u_char		Arp_pln;			//协议地址长度
	u_short		Arp_op;				//操作码，1为请求 2为回复
	u_char		Arp_srcmac[6];		//发送方MAC
	u_char		Arp_srcip[4];		//发送方IP
	u_char		Arp_destmac[6];		//接收方MAC
	u_char		Arp_destip[4];		//接收方IP
} ArpHead;

//定义IP头 
typedef struct _IpHead
{
#if defined(LITTLE_ENDIAN)
	u_char		ihl : 4;
	u_char		version : 4;
#elif defined(BIG_ENDIAN)
	u_char		version : 4;
	u_char		ihl : 4;
#endif
	u_char		tos;			//TOS 服务类型
	u_short		tlen;			//包总长 u_short占两个字节
	u_short		id;				//标识
	u_short		frag_off;		//片位移
	u_char		ttl;			//生存时间
	u_char		proto;			//协议
	u_short		check;			//校验和
	u_int		saddr;			//源地址
	u_int		daddr;			//目的地址
	u_int		opt;			//选项等
} IpHead;

//定义TCP头
typedef struct _TcpHead
{
	u_short		sport;			//源端口地址  16位
	u_short		dport;			//目的端口地址 16位
	u_int		seq;			//序列号 32位
	u_int		ack_seq;		//确认序列号 
#if defined(LITTLE_ENDIAN)
	u_short		res1 : 4,
				doff : 4,
				fin : 1,
				syn : 1,
				rst : 1,
				psh : 1,
				ack : 1,
				urg : 1,
				ece : 1,
				cwr : 1;
#elif defined(BIG_ENDIAN)
	u_short		doff : 4,
				res1 : 4,
				cwr : 1,
				ece : 1,
				urg : 1,
				ack : 1,
				psh : 1,
				rst : 1,
				syn : 1,
				fin : 1;
#endif
	u_short		window;			//窗口大小 16位
	u_short		check;			//校验和 16位
	u_short		urg_ptr;		//紧急指针 16位
	u_int		opt;			//选项
} TcpHead;

/*typedef struct tcphdr
{
u_short sport;				//源端口地址  16位
u_short dport;				//目的端口地址 16位
u_int seq;					//序列号 32位
u_int ack_seq;				//确认序列号
u_short doff_flag;			//头大小、保留位、标志位
u_short window;				//窗口大小 16位
u_short check;				//校验和 16位
u_short urg_ptr;			//紧急指针 16位
u_int opt;					//选项
};*/

//定义UDP头
typedef struct _UdpHead
{
	u_short		sport;			//源端口  16位
	u_short		dport;			//目的端口 16位
	u_short		len;			//数据报长度 16位
	u_short		check;			//校验和 16位	
} UdpHead;

//定义ICMP
typedef struct _IcmpHead
{
	u_char		type;			//8位 类型
	u_char		code;			//8位 代码
	u_char		seq;			//序列号 8位
	u_char		chksum;			//8位校验和
} IcmpHead;

//定义IPv6
typedef struct _Ip6Head
{
	//#if defined(BIG_ENDIAN)
	u_int		version : 4,			//版本
				flowtype : 8,			//流类型
				flowid : 20;			//流标签
/*#elif defined(LITTLE_ENDIAN)
	u_int  flowid:20,			//流标签
	flowtype:8,					//流类型
	version:4;					//版本
#endif*/
	u_short		plen;				//有效载荷长度
	u_char		nh;					//下一个头部
	u_char		hlim;				//跳限制
	u_short		saddr[8];			//源地址
	u_short		daddr[8];			//目的地址
} Ip6Head;

//定义ICMPv6
typedef struct _Icmp6Head
{
	u_char		type;				//8位 类型
	u_char		code;				//8位 代码
	u_char		seq;				//序列号 8位
	u_char		chksum;				//8位校验和
	u_char		op_type;			//选项：类型
	u_char		op_len;				//选项：长度
	u_char		op_ethaddr[6];		//选项：链路层地址
} Icmp6Head;

//对各种包进行计数
typedef struct _PacketCount
{
	int			Num_IP;
	int			Num_IP6;
	int			Num_ARP;
	int			Num_TCP;
	int			Num_UDP;
	int			Num_ICMP;
	int			Num_ICMP6;
	int			Num_HTTP;
	int			Num_OTH;
	int			Num_SUM;
} PacketCount;

//////////////////////////////////////////////////////////////////////////
//要保存的数据结构
typedef struct _DataPacket
{
	char		PacketType[8];	//包类型
	int			Time[6];		//时间
	int			Length;			//长度

	MacHead		*Mac_head;		//链路层包头
	ArpHead		*Arp_head;		//ARP包头
	IpHead		*Ip_head;		//IP包头
	Ip6Head		*Ip6_head;		//IPV6
	IcmpHead	*Icmp_head;		//ICMP包头
	Icmp6Head	*Icmp6_head;	//ICMPv6包头
	UdpHead		*Udp_head;		//UDP包头
	TcpHead		*Tcp_head;		//TCP包头

	void		*App_head;	//应用层包头
} DataPacket;