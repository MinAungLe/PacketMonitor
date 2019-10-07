#pragma once
#define PROTO_ICMP 1
#define PROTO_TCP 6					
#define PROTO_UDP 17					 
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321


//Mac֡ͷ ռ14���ֽ�
typedef struct _MacHead
{
	u_char		dest[6];		//6���ֽ� Ŀ���ַ
	u_char		src[6];			//6���ֽ� Դ��ַ
	u_short		Type;			//2���ֽ� ����
} MacHead;

//ARPͷ
typedef struct _ArpHead
{
	u_short		Arp_hrd;			//Ӳ������
	u_short		Arp_pro;			//Э������
	u_char		Arp_hln;			//Ӳ����ַ����
	u_char		Arp_pln;			//Э���ַ����
	u_short		Arp_op;				//�����룬1Ϊ���� 2Ϊ�ظ�
	u_char		Arp_srcmac[6];		//���ͷ�MAC
	u_char		Arp_srcip[4];		//���ͷ�IP
	u_char		Arp_destmac[6];		//���շ�MAC
	u_char		Arp_destip[4];		//���շ�IP
} ArpHead;

//����IPͷ 
typedef struct _IpHead
{
#if defined(LITTLE_ENDIAN)
	u_char		ihl : 4;
	u_char		version : 4;
#elif defined(BIG_ENDIAN)
	u_char		version : 4;
	u_char		ihl : 4;
#endif
	u_char		tos;			//TOS ��������
	u_short		tlen;			//���ܳ� u_shortռ�����ֽ�
	u_short		id;				//��ʶ
	u_short		frag_off;		//Ƭλ��
	u_char		ttl;			//����ʱ��
	u_char		proto;			//Э��
	u_short		check;			//У���
	u_int		saddr;			//Դ��ַ
	u_int		daddr;			//Ŀ�ĵ�ַ
	u_int		opt;			//ѡ���
} IpHead;

//����TCPͷ
typedef struct _TcpHead
{
	u_short		sport;			//Դ�˿ڵ�ַ  16λ
	u_short		dport;			//Ŀ�Ķ˿ڵ�ַ 16λ
	u_int		seq;			//���к� 32λ
	u_int		ack_seq;		//ȷ�����к� 
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
	u_short		window;			//���ڴ�С 16λ
	u_short		check;			//У��� 16λ
	u_short		urg_ptr;		//����ָ�� 16λ
	u_int		opt;			//ѡ��
} TcpHead;

/*typedef struct tcphdr
{
u_short sport;				//Դ�˿ڵ�ַ  16λ
u_short dport;				//Ŀ�Ķ˿ڵ�ַ 16λ
u_int seq;					//���к� 32λ
u_int ack_seq;				//ȷ�����к�
u_short doff_flag;			//ͷ��С������λ����־λ
u_short window;				//���ڴ�С 16λ
u_short check;				//У��� 16λ
u_short urg_ptr;			//����ָ�� 16λ
u_int opt;					//ѡ��
};*/

//����UDPͷ
typedef struct _UdpHead
{
	u_short		sport;			//Դ�˿�  16λ
	u_short		dport;			//Ŀ�Ķ˿� 16λ
	u_short		len;			//���ݱ����� 16λ
	u_short		check;			//У��� 16λ	
} UdpHead;

//����ICMP
typedef struct _IcmpHead
{
	u_char		type;			//8λ ����
	u_char		code;			//8λ ����
	u_char		seq;			//���к� 8λ
	u_char		chksum;			//8λУ���
} IcmpHead;

//����IPv6
typedef struct _Ip6Head
{
	//#if defined(BIG_ENDIAN)
	u_int		version : 4,			//�汾
				flowtype : 8,			//������
				flowid : 20;			//����ǩ
/*#elif defined(LITTLE_ENDIAN)
	u_int  flowid:20,			//����ǩ
	flowtype:8,					//������
	version:4;					//�汾
#endif*/
	u_short		plen;				//��Ч�غɳ���
	u_char		nh;					//��һ��ͷ��
	u_char		hlim;				//������
	u_short		saddr[8];			//Դ��ַ
	u_short		daddr[8];			//Ŀ�ĵ�ַ
} Ip6Head;

//����ICMPv6
typedef struct _Icmp6Head
{
	u_char		type;				//8λ ����
	u_char		code;				//8λ ����
	u_char		seq;				//���к� 8λ
	u_char		chksum;				//8λУ���
	u_char		op_type;			//ѡ�����
	u_char		op_len;				//ѡ�����
	u_char		op_ethaddr[6];		//ѡ���·���ַ
} Icmp6Head;

//�Ը��ְ����м���
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
//Ҫ��������ݽṹ
typedef struct _DataPacket
{
	char		PacketType[8];	//������
	int			Time[6];		//ʱ��
	int			Length;			//����

	MacHead		*Mac_head;		//��·���ͷ
	ArpHead		*Arp_head;		//ARP��ͷ
	IpHead		*Ip_head;		//IP��ͷ
	Ip6Head		*Ip6_head;		//IPV6
	IcmpHead	*Icmp_head;		//ICMP��ͷ
	Icmp6Head	*Icmp6_head;	//ICMPv6��ͷ
	UdpHead		*Udp_head;		//UDP��ͷ
	TcpHead		*Tcp_head;		//TCP��ͷ

	void		*App_head;	//Ӧ�ò��ͷ
} DataPacket;