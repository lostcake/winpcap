// 本程序的协议分析脉络为：
// 数据链路层     网络层       传输层         应用层
//        +------IP---+------TCP
//        |           |
// MAC ---+           +------UDP---+------NBNS
//        |                        |
//        +------ARP               +------NBDS
// 其他协议大多能分析出结果（即上层使用了何种协议），但没有深入分析
// 【说明】在我的测试中抓取到的数据包中，使用UDP协议占了八成以上，其中大多数采用NBNS协议，
// 少部分使用NBDS协议或直接携带数据。此外还有少部分使用TCP协议的数据包，检查发现它们的上层
// 协议大多是HTTPS，该协议经过了加密处理，因此并未深入分析。还有少部分数据包使用了ARP协议
// 和IPv6协议，由于IPv6协议相较IPv4协议复杂一些，这里没有进行深入分析。在多次的实验中并未
// 发现使用其他协议的数据包，这一结果和我用WireShark得到的结果基本一致。

#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <tchar.h> 
#include <winsock2.h>

#define HAVE_REMOTE
#include <pcap.h>

#define N 1000

using namespace std;

/* 以太网协议格式 */
// 以太网的首部为：
// 目的地址（6字节） | 源地址（6字节） | 类型（2字节）
// 目的地址FF:FF:FF:FF:FF:FF表示广播地址，实验捕获的大量数据包都属此类情况
struct ether_header
{
	u_int8_t ether_dhost[6];  //目的以太网地址
	u_int8_t ether_shost[6];  //源以太网地址
	u_int16_t ether_type;     //以太网类型
};

/* IPv4协议格式 */
// IPv4的报文格式为：
// 0 - - - 4 - - - 8 - - - - - - - 16 - - - - - - - - - - - - - -31
// |  版本  | 头长度 |    服务质量     |            总长度             |
// |              标识              | 标志  |         段偏移         |
// |     生存时间    |    协议类型     |            校验和             |
// |                            源IP地址                           |
// |                           目的IP地址                           |
// |                              选项                             |
// |                              数据                             ..
struct ipv4_header
{
	u_int8_t ip_header_length : 4, ip_version : 4; //首部长度、版本
	u_int8_t ip_tos;        //服务质量
	u_int16_t ip_length;     //长度
	u_int16_t ip_id;         //标识
	u_int16_t ip_off;        //偏移
	u_int8_t ip_ttl;        //生存时间
	u_int8_t ip_protocol;   //协议类型
	u_int16_t ip_checksum;  //校验和
	struct in_addr ip_source_address;      //源IP地址
	struct in_addr ip_destination_address; //目的IP地址
};

/* ARP协议格式 */
// ARP的报文格式为：
// 0 - - - - - - - 8 - - - - - - - 16 - - - - - - - - - - - - - -31
// |            硬件类型             |           协议类型            |
// |   硬件地址长度  |   协议地址长度   |            操作码             |
// |                        源站物理地址（前4字节）                   |
// |      源站物理地址（后2字节）       |       源站IP地址（前2字节）     |
// |       源站IP地址（后2字节）       |      目的站物理地址（前2字节）   |
// |                      目的站物理地址（后4字节）                    |
// |                       目的站IP地址（4字节）                      |
struct arp_header
{
	u_int16_t arp_hardware_type;  //硬件类型
	u_int16_t arp_protocol_type;  //协议类型
	u_int8_t arp_hardware_length; //硬件地址长度
	u_int8_t arp_protocol_length; //协议地址长度
	u_int16_t arp_opreation_code; //操作码

	//源以太网地址与源IP地址：
	u_int8_t arp_source_ethernet_address[6];
	u_int8_t arp_source_ip_address[4];

	//目的以太网地址与目的IP地址：
	u_int8_t arp_destination_ethernet_address[6];
	u_int8_t arp_destination_ip_address[4];
};

/* TCP协议格式 */
// TCP的报文格式为：
//0 - - - 4 - - - 8 - - - - - - - 16 - - - - - - - - - - - - - -31
// |            源端口号             |         目的端口号            |
// |                             序列号                           |
// |                           确认序列号                          |
// |首部长度|    保留   |     标记    |           窗口大小            |
// |            校验和              |           紧急指针            |
// |                              选项                            |
// |                              数据                            |
//当采用小端方案时（如我的电脑），则第四行的首部长度、保留字和标记要有所差别，这里按照小端方案定义的
struct tcp_header
{
	u_int16_t tcp_source_port;      //源端口号
	u_int16_t tcp_destination_port; //目的端口号
	u_int32_t tcp_sequence;         //序列号
	u_int32_t tcp_ack_sequence;     //确认序列号
	u_int8_t tcp_reserved : 4, tcp_offset : 4; //保留字与首部长度
	u_int8_t tcp_flags;             //标记
	u_int16_t tcp_windows;          //窗口大小
	u_int16_t tcp_checksum;         //校验和
	u_int16_t tcp_urgent_pointer;   //紧急字段指针

	u_int8_t tcp_datas[N];             //数据
};

/* UDP协议格式 */
// UDP的报文格式为：首部字段 | 数据字段
// 首部字段的格式为：
// 源端口号（2字节） | 目的端口号（2字节） | 长度（2字节） | 校验和（2字节）
struct udp_header
{
	u_int16_t udp_source_port;      //源端口号
	u_int16_t udp_destination_port; //目的端口号
	u_int16_t udp_length;           //长度
	u_int16_t udp_checksum;         //校验和
};

/* NBNS协议格式 */
// NBNS的报文格式为：
// 0 - - - - - - - - - - - - - - - 16 - - - - - - - - - - - - - -31
// |             事务ID             |           通用标志            |
// |           问题记录个数           |         回答记录个数          |
// |           权威记录个数           |         附加记录个数          |
// |                        问题记录（若干字节）                     ...
// |                        回答记录（若干字节）                     ...
// |                        权威记录（若干字节）                     ...
// |                        附加记录（若干字节）                     ...
struct nbns_header
{
	u_int16_t nbns_transaction_id; //事务ID
	u_int16_t nbns_flags;          //通用标志
	u_int16_t nbns_questions;      //问题记录个数
	u_int16_t nbns_answers;        //回答记录个数
	u_int16_t nbns_authority;      //权威记录个数
	u_int16_t nbns_additonal;      //附加记录个数
	u_int8_t datas[N];             //数据
};

/* NBDS协议格式 */
// NBDS的报文格式为：
// 0 - - - - - - - 8 - - - - - - - 16 - - - - - - - - - - - - - -31
// |    消息类型     |      标志      |          数据报编号           |
// |                             源IP地址                          |
// |             源端口              |          数据报长度           |
// |           报文偏移量             |            数据              |
// |                              数据                            ...
// 当消息类型字段内容为0x10、0x11或0x12时，分别说明NetBIOS的数据报为发送给相邻的
// 特定主机、发送给直连网段内的全部主机还是广播给全部主机的数据报，此时报文格式为：
// 0 - - - - - - - 8 - - - - - - - 16 - - - - - - - - - - - - - -31
// |    消息类型     |      标志      |          数据报编号           |
// |                             源IP地址                          |
// |             源端口              |          数据报长度           |
// |            包偏移量             |       源名字（若干字节）        |
// |                         源名字（若干字节）                     ...
// |                        目的名字（若干字节）                     ...
// |                        用户数据（若干字节）                     ...
struct nbds_header
{
	u_int8_t nbds_message_type;     //消息类型
	u_int8_t nbds_flags;            //标志
	u_int16_t nbds_datagram_id;     //数据报编号
	struct in_addr nbds_source_ip;       //源IP地址
	u_int16_t nbds_source_port;     //源端口
	u_int16_t nbds_datagram_length; //数据报长度
	u_int16_t nbds_packet_offset;   //报文偏移量
};

/* packet handler 函数原型 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

/* NBNS协议的回调函数 */
//应用层的协议，该函数的参数和其他回调函数相同，分别为：
//param，数据包存储的文件指针
//header，堆文件包的结构体首部指针，可得到时间值、数据包长度
//pkt_data，指向数据包内容的指针
//pkt_length，数据包的长度
void nbns_packet_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data, int pkt_length)
{
	struct nbns_header *nbns_protocol;

	nbns_protocol = (struct nbns_header*)(pkt_data + 14 + 20 + 8);

	printf("-----*  应用层：NBNS协议  *-----\n");
	printf("事务编号：%d\n", ntohs(nbns_protocol->nbns_transaction_id));
	printf("通用标志：%02x\n", ntohs(nbns_protocol->nbns_flags));
	printf("问题记录个数：%d\n", ntohs(nbns_protocol->nbns_questions));
	printf("回答记录个数：%d\n", ntohs(nbns_protocol->nbns_answers));
	printf("权威记录个数：%d\n", ntohs(nbns_protocol->nbns_authority));
	printf("附加记录个数：%d\n", ntohs(nbns_protocol->nbns_additonal));

	printf("记录：");
	for (int i = 0; i < pkt_length - 12; i++)
	{
		if (i % 10 == 0) printf("\n\t");
		printf("%02x ", nbns_protocol->datas[i]);
	}
	printf("\n");
}

/* NBDS协议的回调函数 */
//应用层的协议，该函数的参数和其他回调函数相同，分别为：
//param，数据包存储的文件指针
//header，堆文件包的结构体首部指针，可得到时间值、数据包长度
//pkt_data，指向数据包内容的指针
void nbds_packet_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct nbds_header *nbds_protocol;

	nbds_protocol = (struct nbds_header*)(pkt_data + 14 + 20 + 8);

	printf("-----*  应用层：NBDS协议  *-----\n");
	printf("消息类型：%02x\n", ntohs(nbds_protocol->nbds_message_type));
	printf("标志：%02x\n", ntohs(nbds_protocol->nbds_flags));
	printf("数据报编号：%d\n", ntohs(nbds_protocol->nbds_datagram_id));
	printf("源IP地址：%s\n", inet_ntoa(nbds_protocol->nbds_source_ip));
	printf("源端口：%d\n", ntohs(nbds_protocol->nbds_source_port));
	printf("数据报长度：%d\n", ntohs(nbds_protocol->nbds_datagram_length));
	printf("报文偏移量：%d\n", ntohs(nbds_protocol->nbds_packet_offset));

	printf("记录：");
	pkt_data += 56;  // 14(MAC_head)+20(IP_head)+8(UDP_head)+14(NBDS_head)
	for (int i = 0; i < ntohs(nbds_protocol->nbds_datagram_length); i++)
	{
		if (i % 10 == 0) printf("\n\t");
		printf("%02x ", *pkt_data++);
	}
	printf("\n");
}

/* TCP协议的回调函数 */
//传输层的协议，该函数的参数和其他回调函数相同，分别为：
//param，数据包存储的文件指针
//header，堆文件包的结构体首部指针，可得到时间值、数据包长度
//pkt_data，指向数据包内容的指针
void tcp_packet_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data, int pkt_length)
{
	struct tcp_header *tcp_protocol;
	u_char flags;
	u_short source_port;
	u_short destination_port;

	tcp_protocol = (struct tcp_header*)(pkt_data + 14 + 20);
	source_port = ntohs(tcp_protocol->tcp_source_port);
	destination_port = ntohs(tcp_protocol->tcp_destination_port);
	flags = tcp_protocol->tcp_flags;

	printf("-----*  传输层：TCP协议  *-----\n");
	printf("源端口号：%d\n", source_port);
	printf("目的端口号：%d\n", destination_port);
	printf("序列码：%u\n", ntohl(tcp_protocol->tcp_sequence));
	printf("确认号：%u\n", ntohl(tcp_protocol->tcp_ack_sequence));
	printf("首部长度：%d\n", tcp_protocol->tcp_offset * 4);
	printf("保留字：%d\n", tcp_protocol->tcp_reserved);
	printf("标记：");
	//8个标记各占一位，采用大端方案时分别为CWR ECE URG ACK PSH RST SYN FIN
	//这里采用的是小端方案，分别为FIN SYN RST PSH ACK URG ECE CWR
	if (flags & 0x01) printf("拥塞CWR ");
	if (flags & 0x02) printf("拥塞ECE ");
	if (flags & 0x04) printf("紧急URG ");
	if (flags & 0x08) printf("确认ACK ");
	if (flags & 0x10) printf("推送PSH ");
	if (flags & 0x20) printf("复位RST ");
	if (flags & 0x40) printf("同步SYN ");
	if (flags & 0x80) printf("终止FIN ");
	printf("\n");
	printf("窗口大小：%d\n", ntohs(tcp_protocol->tcp_windows));
	printf("校验和：%d\n", ntohs(tcp_protocol->tcp_checksum));
	printf("紧急指针：%d\n", ntohs(tcp_protocol->tcp_urgent_pointer));

	//端口在1024内的为固定端口，部分值如下。在1024以上的为动态端口。
	switch (destination_port)
	{
	case 80:
		printf("上层协议为HTTP协议\n");
		break;
	case 21:
		printf("上层协议为FTP协议\n");
		break;
	case 23:
		printf("上层协议为TELNET协议\n");
		break;
	case 25:
		printf("上层协议为SMTP协议\n");
		break;
	case 110:
		printf("上层协议为POP3协议\n");
		break;
	case 443:
		printf("上层协议为HTTPS协议\n");
		break;
	default:
		break;
	}
	
	// 因为TCP协议的报头中可能有选项，选项的长度是由这里的“首部长度”决定的（首部长度需要乘4得到真正的
	// 报文头所占的字节数），报文头部前20字节是固定的，因此选项的长度为“首部长度*4-20”个字节。选项后
	// 面的内容（如果存在）则为数据部分，这里捕获到的含数据部分的数据包所用上层协议基本全部是HTTPS协议，
	// 无法进行进一步分析。
	if (tcp_protocol->tcp_offset > 5)
	{
		printf("选项：");
		for (int i = 0; i < tcp_protocol->tcp_offset * 4 - 20; i++)
		{
			if (i % 10 == 0) printf("\n\t");
			printf("%02x ", tcp_protocol->tcp_datas[i]);
		}
		printf("\n");
	}
	if (pkt_length > tcp_protocol->tcp_offset * 4)
	{
		printf("数据：");
		for (int i = tcp_protocol->tcp_offset * 4 - 20; i < pkt_length - 20; i++)
		{
			if (i % 10 == 0) printf("\n\t");
			printf("%02x ", tcp_protocol->tcp_datas[i]);
		}
		printf("\n");
	}
}

/* UDP协议的回调函数 */
//传输层的协议，该函数的参数和其他回调函数相同，分别为：
//param，数据包存储的文件指针
//header，堆文件包的结构体首部指针，可得到时间值、数据包长度
//pkt_data，指向数据包内容的指针
void udp_packet_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct udp_header *udp_protocol;
	u_short source_port;
	u_short destination_port;

	udp_protocol = (struct udp_header*)(pkt_data + 14 + 20);
	source_port = ntohs(udp_protocol->udp_source_port);
	destination_port = ntohs(udp_protocol->udp_destination_port);

	printf("-----*  传输层：UDP协议  *-----\n");
	printf("源端口号：%d\n",source_port);
	printf("目的端口号：%d\n", destination_port);
	printf("长度：%d\n", ntohs(udp_protocol->udp_length));
	printf("校验和：%d\n", ntohs(udp_protocol->udp_checksum));

	switch (destination_port)
	{
	case 53:
		printf("上层协议为域名解析服务DNS\n");
		break;
	case 69:
		printf("上层协议为简单网络管理协议SNMP\n");
		break;
	case 137:
		printf("上层协议为NetBIOS名字服务NBNS\n");
		nbns_packet_callback(param, header, pkt_data, ntohs(udp_protocol->udp_length)-8);
		break;
	case 138:
		printf("上层协议为NetBIOS数据报服务NBDS\n");
		nbds_packet_callback(param, header, pkt_data);
		break;
	case 139:
		printf("上层协议为NetBIOS会话服务\n");
		break;
	case 161:
		printf("上层协议为简单网络管理协议SNMP\n");
		break;
	default:
		break;
	}

	if (destination_port >= 1024)
	{
		printf("数据：");
		pkt_data += 42;  // 14(MAC_head)+20(IP_head)+8(UDP_head);
		for (int i = 0; i < ntohs(udp_protocol->udp_length) - 8; i++)
		{
			if (i % 10 == 0) printf("\n\t");
			printf("%02x ", *pkt_data++);
		}
		printf("\n");
	}
}

/* IPv4协议的回调函数 */
//网络层的协议，该函数的参数和其他回调函数相同，分别为：
//param，数据包存储的文件指针
//header，堆文件包的结构体首部指针，可得到时间值、数据包长度
//pkt_data，指向数据包内容的指针
void ipv4_packet_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct ipv4_header *ip_protocol;
	u_int offset;
	
	ip_protocol = (struct ipv4_header*)(pkt_data + 14);
	offset = ntohs(ip_protocol->ip_off);

	printf("-----* 网络层：IP协议 *-----\n");
	printf("版本号：%d\n", ip_protocol->ip_version);
	printf("首部长度：%d\n", ip_protocol->ip_header_length * 4);
	printf("服务质量：%d\n", ip_protocol->ip_tos);
	printf("总长度：%d\n", ntohs(ip_protocol->ip_length));
	printf("标识：%d\n", ntohs(ip_protocol->ip_id));
	printf("偏移量：%d\n", (offset & 0x1fff) * 8);
	printf("生存时间：%d\n", ip_protocol->ip_ttl);
	printf("协议类型：%d\n", ip_protocol->ip_protocol);
	printf("校验和：%d\n", ntohs(ip_protocol->ip_checksum));
	printf("源IP地址：%s\n", inet_ntoa(ip_protocol->ip_source_address));
	printf("目的IP地址：%s\n", inet_ntoa(ip_protocol->ip_destination_address));

	switch (ip_protocol->ip_protocol)
	{
	case 1:
		printf("上层协议为ICMP协议\n");
		break;
	case 6:
		printf("上层协议为TCP协议\n");
		tcp_packet_callback(param, header, pkt_data, ntohs(ip_protocol->ip_length) - 20);
		break;
	case 17:
		printf("上层协议为UDP协议\n");
		udp_packet_callback(param, header, pkt_data);
		break;
	default:
		break;
	}
}

/* ARP协议的回调函数 */
//网络层的协议，该函数的参数和其他回调函数相同，分别为：
//param，数据包存储的文件指针
//header，堆文件包的结构体首部指针，可得到时间值、数据包长度
//pkt_data，指向数据包内容的指针
void arp_packet_callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct arp_header *arp_protocol;
	u_short operation_code;
	u_char *mac_string;
	struct in_addr source_ip_address;
	struct in_addr destination_ip_address;

	arp_protocol = (struct arp_header*)(pkt_data + 14);
	operation_code = ntohs(arp_protocol->arp_opreation_code);

	printf("-----*  网络层：ARP协议  *-----\n");
	printf("硬件类型：%d\n", ntohs(arp_protocol->arp_hardware_type));
	printf("协议类型：%04x\n", ntohs(arp_protocol->arp_protocol_type));
	printf("硬件地址长度：%d\n", arp_protocol->arp_hardware_length);
	printf("协议地址长度：%d\n", arp_protocol->arp_protocol_length);
	mac_string = arp_protocol->arp_source_ethernet_address;
	printf("源以太网地址：");
	for (int i = 0; i < 6; i++)
	{
		printf("%02x", *(mac_string + i));
		if (i != 5) printf(":");
		else printf("\n");
	}
	memcpy((void*)&source_ip_address, (void*)&arp_protocol->arp_source_ip_address, sizeof(struct in_addr));
	printf("源IP地址：%s\n", inet_ntoa(source_ip_address));
	mac_string = arp_protocol->arp_destination_ethernet_address;
	printf("目的以太网地址：");
	for (int i = 0; i < 6; i++)
	{
		printf("%02x", *(mac_string + i));
		if (i != 5) printf(":");
		else printf("\n");
	}
	memcpy((void*)&destination_ip_address, (void*)&arp_protocol->arp_destination_ip_address, sizeof(struct in_addr));
	printf("目的IP地址：%s\n", inet_ntoa(destination_ip_address));

	switch (operation_code)
	{
	case 1:
		printf("ARP操作：ARP请求协议\n");
		break;
	case 2:
		printf("ARP操作：ARP应答协议\n");
		break;
	case 3:
		printf("ARP操作：RARP请求协议\n");
		break;
	case 4:
		printf("ARP操作：RARP应答协议\n");
		break;
	default:
		break;
	}
}

int _tmain(int argc, _TCHAR* argv[])     //_tmain就是UNICODE版的main
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 获取（本地）网络设备列表 */
	//函数返回0表示查找成功，-1表示查找失败。参数为：
	//source，指定本地适配器或远程适配器
	//auth，指向pcap_rmtauth结构的指针，保存连接到远程主机上的授权信息，查询本地设备时无用处设置为NULL
	//alldevs，指向pcap_if_t结构的指针，存放获取的适配器数据，若查找失败则值为NULL
	//errbuf，存放查找失败的信息
	if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//在屏幕上输出错误信息
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	//pcap_if_t结构与pcap_if相同，内容有：
	//next，指向下一个元素的指针，若为NULL则表示链表结束
	//name，指向字符串的指针，是WinPcap为网络接口卡分配的名字，用于打开网卡
	//description，设备的文本描述符
	//addresses，地址指针，指向接口地址列表的第一个元素
	//flags，标志位，看接口是不是回送设备
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开设备 */
	//pcap_open函数返回指向pcap_t结构的指针，若调用失败返回NULL，函数的参数有:
	//source，以\0终止的字符串，包含要打开的源名称
	//snaplen，必须保留的包长度，此处65535保证能捕获到不同数据链路层上的每个数据包的全部内容
	//flags，保留捕获数据包可能需要的标志，此处PCAP_OPENFLAG_PROMISCUOUS表示混杂模式
	//read_timeout，以毫秒为单位读取超时时间
	//auth，指向pcap_rmtauth结构的指针，保存连接到远程主机上的授权信息，查询本地设备时无用处设置为NULL
	//errbuf，存放失败信息
	if ((adhandle = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕获 */
	//该函数用来捕获数据包，参数为：
	//p，由pcap_open()返回的所打开适配器的指针
	//cnt，捕获数据包的个数，设置为0则表示无限捕获
	//callback，回调函数的名称，每次捕获一个数据包都会调用该函数
	//user，留作用户使用，此处为NULL
	pcap_loop(adhandle, 20, packet_handler, NULL);

	getchar();

	return 0;
}

/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
//该函数为数据链路层的输出，参数为：
//param，数据包存储的文件指针
//header，堆文件包的结构体首部指针，可得到时间值、数据包长度
//pkt_data，指向数据包内容的指针
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	//下三项为以太网类型、以太网地址和以太网协议变量
	u_short ethernet_type;
	u_char *mac_string;
	struct ether_header *ethernet_protocol;

	static int count = 1;

	//过滤上层为IP协议的数据包
	//ethernet_protocol = (struct ether_header*)pkt_data;
	//ethernet_type = ntohs(ethernet_protocol->ether_type);
	//if (ethernet_type == 0x0800) return;

	printf("============================================================\n");
	printf("捕获第%d个数据包：\n", count++);

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("\t时间戳：%s,%.6ld\n\t数据包长度：%d\n", timestr, header->ts.tv_usec, header->len);

	printf("-----*  数据链路层：以太网协议  *-----\n");
	ethernet_protocol = (struct ether_header*)pkt_data;
	//ntohs函数用于将一个16位数以网络字节顺序转换为主机字节顺序
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	printf("类型：%04x\n", ethernet_type);

	mac_string = ethernet_protocol->ether_shost;
	printf("MAC帧源以太网地址：");
	for (int i = 0; i < 6; i++)
	{
		printf("%02x", *(mac_string + i));
		if (i != 5) printf(":");
		else printf("\n");
	}
	mac_string = ethernet_protocol->ether_dhost;
	printf("MAC帧目的以太网地址：");
	for (int i = 0; i < 6; i++)
	{
		printf("%02x", *(mac_string + i));
		if (i != 5) printf(":");
		else printf("\n");
	}

	switch (ethernet_type)
	{
	case 0x0800:
		printf("上层协议为IP协议\n");
		ipv4_packet_callback(param, header, pkt_data);
		break;
	case 0x0806:
		printf("上层协议为ARP协议\n");
		arp_packet_callback(param, header, pkt_data);
		break;
	case 0x8035:
		printf("上层协议为RARP协议\n");
		break;
	case 0x814C:
		printf("上层协议为简单网络管理协议SNMP\n");
		break;
	case 0x8137:
		printf("上层协议是因特网包交换协议IPX\n");
		break;
	case 0x86DD:
		printf("上层协议是IPv6协议\n");
		break;
	case 0x880B:
		printf("上层协议是点对点协议PPP\n");
		break;
	default:
		break;
	}
}