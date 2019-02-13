#include "capthread.h"
#include <QDebug>

CapThread::CapThread(DevInfo* nic)
{
    this->nic = nic;
    qDebug()<<this->nic->name;
}

void CapThread::CapThread::quit()
{
    pcap_close(adhandle);
}

void CapThread::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask = 0xffffff;
    char packet_filter[] = "ip and udp";
    struct bpf_program fcode;

    printf(this->nic->name.toLocal8Bit().data());

    /* 打开适配器 */
    if ( (adhandle= pcap_open(this->nic->name.toLocal8Bit().data(),  // 设备名
                              65536,     // 要捕捉的数据包的部分
                              // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
                              1000,      // 读取超时时间
                              nullptr,      // 远程机器验证
                              errbuf     // 错误缓冲池
                              ) ) == nullptr)
    {
        qDebug("\nUnable to open the adapter. %s is not supported by WinPcap\n");
    }

    /* 检查数据链路层，为了简单，只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        qDebug("\nThis program works only on Ethernet networks.\n");
    }

    /* 如果接口没有地址，默认为一个C类的掩码 */
    if(!nic->ipAddresses.empty())
        /* 获得接口第一个地址的掩码 */
        for(auto a : nic->ipAddresses){
            if(!a->netmask.isEmpty()){
                netmask=ipConvertToInt(a->netmask);
                break;
            }
        }

    //编译过滤器
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        qDebug("\nUnable to compile the packet filter. Check the syntax.\n");
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        qDebug("\nError setting the filter.\n");
    }

    qDebug("listening on ...");

    /* 开始捕捉 */
    pcap_loop(adhandle, 0, packet_handler, nullptr);
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void CapThread::packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* 打印数据包的时间戳和长度 */
    qDebug("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    /* 获得IP数据包头部的位置 */
    ih = (ip_header *) (pkt_data +
                        14); //以太网头部长度

    /* 获得UDP首部的位置 */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* 将网络字节序列转换成主机字节序列 */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    /* 打印IP地址和UDP端口 */
    qDebug("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
           ih->saddr.byte1,
           ih->saddr.byte2,
           ih->saddr.byte3,
           ih->saddr.byte4,
           sport,
           ih->daddr.byte1,
           ih->daddr.byte2,
           ih->daddr.byte3,
           ih->daddr.byte4,
           dport);
}

u_int CapThread::ipConvertToInt(QString ip)
{
    QStringList strList = ip.split(".");
    QString uintStr = "0x";
    for(QString str : strList){
        auto uint = str.toUInt();
        uintStr.append(QString(uint));
    }
    return uintStr.toUInt();
}
