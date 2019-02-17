#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QThread>
#include <QVector>
#include <QMainWindow>
#include "wdpcap.h"
#include "devinfo.h"

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321

/* 数据包数据 */
struct pktData {
    const struct pcap_pkthdr *header;
    const u_char *pkt_data;
};

class CapThread: public QThread
{
    Q_OBJECT
public:
    CapThread(QMainWindow *w, DevInfo* nic);
    void run();
    void quit();
private:
    pcap_t *adhandle;
    DevInfo* nic;
    QVector<pktData *> pktVector;
    QMainWindow *w;
    u_int ipConvertToInt(QString ip);
    void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

    QStringList ethernet_parser(uint pktLen, const u_char *pkt_data);
    QStringList arp_parser(const u_char *pkt_data);
    QStringList ip_parser(uint pktLen, const u_char *pkt_data);
signals:
    void sendTableData(DataTableItem *dtItem);
};

/* MAC 帧头部， Ethernet II 协议报头 */
struct eth_header
{
    u_char dest[6];			//6个字节 目标地址
    u_char src[6];				//6个字节 源地址
    u_short type;				//2个字节 类型
};

/* ARP 协议头部 */
struct arp_header
{
    u_short ar_hw;						//硬件类型
    u_short ar_prot;						//协议类型
    u_char ar_hln;						//硬件地址长度
    u_char ar_pln;						//协议地址长度
    u_short ar_op;						//操作码，1为请求 2为回复
    u_char ar_srcmac[6];			//发送方MAC
    u_char ar_srcip[4];				//发送方IP
    u_char ar_destmac[6];			//接收方MAC
    u_char ar_destip[4];				//接收方IP
};


/* 4字节的IP地址 */
struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

/* IPv4 首部 */
struct ip_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
};

//定义IP头
struct ip_header
{
#if defined(LITTLE_ENDIAN)
    u_char ihl:4;
    u_char version:4;
#elif defined(BIG_ENDIAN)
    u_char version:4;
    u_char  ihl:4;
#endif
    u_char tos;				//TOS 服务类型
    u_short tlen;			//包总长 u_short占两个字节
    u_short id;				//标识
    u_short frag_off;	//片位移
    u_char ttl;				//生存时间
    u_char proto;		//协议
    u_short check;		//校验和
    u_int saddr;			//源地址
    u_int daddr;			//目的地址
    u_int	op_pad;		//选项等
};

//定义TCP头
struct tcphdr
{
    u_short sport;							//源端口地址  16位
    u_short dport;							//目的端口地址 16位
    u_int seq;									//序列号 32位
    u_int ack_seq;							//确认序列号
#if defined(LITTLE_ENDIAN)
    u_short res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(BIG_ENDIAN)
    u_short doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#endif
    u_short window;					//窗口大小 16位
    u_short check;						//校验和 16位
    u_short urg_ptr;					//紧急指针 16位
    u_int opt;								//选项
};

/* UDP 首部*/
struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
};

//定义ICMP
struct icmphdr
{
    u_char type;			//8位 类型
    u_char code;			//8位 代码
    u_char seq;			//序列号 8位
    u_char chksum;		//8位校验和
};

//定义IPv6
struct iphdr6
{
    u_int version:4,				//版本
        flowtype:8,			//流类型
        flowid:20;				//流标签
    u_short plen;					//有效载荷长度
    u_char nh;						//下一个头部
    u_char hlim;					//跳限制
    u_short saddr[8];			//源地址
    u_short daddr[8];			//目的地址
};

//定义ICMPv6
struct icmphdr6
{
    u_char type;			//8位 类型
    u_char code;			//8位 代码
    u_char seq;			//序列号 8位
    u_char chksum;		//8位校验和
    u_char op_type;	//选项：类型
    u_char op_len;		//选项：长度
    u_char op_ethaddr[6];		//选项：链路层地址
};

#endif // CAPTHREAD_H
