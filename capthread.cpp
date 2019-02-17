#include "capthread.h"
#include <QMessageBox>
#include <QDebug>

CapThread::CapThread(QMainWindow *w, DevInfo* nic)
{
    this->nic = nic;
    this->w = w;
}

void CapThread::CapThread::quit()
{
    pcap_close(adhandle);
}

void CapThread::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask = 0xffffff;
    char packet_filter[] = "arp";
    struct bpf_program fcode;
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

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
    //pcap_loop(adhandle, 0, packet_handler, nullptr);
    /* 获取数据包 */
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

        if(res == 0)
            /* 超时时间到 */
            continue;

        /* 申请存储内存空间 */
        pktData *data = (pktData *)malloc(sizeof (pktData));
        memset(data, 0, sizeof (pktData));

        if(data == nullptr){
            QMessageBox::warning(w, "Error", "Memory Full");
            break;
        }
        data->header = header;
        data->pkt_data = pkt_data;
        pktVector.push_back(data);

        packet_handler(nullptr, pktVector.back()->header, pktVector.back()->pkt_data);
    }

    if(res == -1){
        qDebug("Error reading the packets: %s\n", pcap_geterr(adhandle));
    }
}

/* 用于解析，当收到每一个数据包时会调用 */
void CapThread::packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;
    DataTableItem *dtItem = new DataTableItem;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* 打印数据包的时间戳和长度 */
    qDebug("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
    dtItem->timeStamp = QString(timestr) + "." + QString::number(header->ts.tv_usec);
    dtItem->len = header->len;

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
    dtItem->source = QString("%1.%2.%3.%4").arg(ih->saddr.byte1).arg(ih->saddr.byte2).
            arg(ih->saddr.byte3).arg(ih->saddr.byte4);
    dtItem->dest = QString("%1.%2.%3.%4").arg(ih->daddr.byte1).arg(ih->daddr.byte2).
            arg(ih->daddr.byte3).arg(ih->daddr.byte4);
    dtItem->info.append(QString("Port: %1 to Port: %2 ").arg(sport).arg(dport));
    ethernet_parser(header->len, pkt_data);
    qDebug()<<"continue";
    emit sendTableData(dtItem);
}


QStringList CapThread::ethernet_parser(uint pktLen, const u_char *pkt_data)
{
    eth_header *eth;
    QStringList dataStr;

    eth = (eth_header *)pkt_data;
    eth->type = ntohs(eth->type);

    /* MAC帧数据：
     *  [ Destination ] [ Source ] [ Type  ] [ Data ] [  FCS  ]
     *  [    6 Bytes  ] [ 6 Bytes] [2 Bytes] -------- [4 Bytes]
     */
    dataStr << QString("Destination: %1:%2:%3:%4:%5:%6")
               .arg(eth->dest[0], 2, 16, QLatin1Char('0'))
            .arg(eth->dest[1], 2, 16, QLatin1Char('0'))
            .arg(eth->dest[2], 2, 16, QLatin1Char('0'))
            .arg(eth->dest[3], 2, 16, QLatin1Char('0'))
            .arg(eth->dest[4], 2, 16, QLatin1Char('0'))
            .arg(eth->dest[5], 2, 16, QLatin1Char('0'))
            << QString("Source: %1:%2:%3:%4:%5:%6")
               .arg(eth->src[0], 2, 16, QLatin1Char('0'))
            .arg(eth->src[1], 2, 16, QLatin1Char('0'))
            .arg(eth->src[2], 2, 16, QLatin1Char('0'))
            .arg(eth->src[3], 2, 16, QLatin1Char('0'))
            .arg(eth->src[4], 2, 16, QLatin1Char('0'))
            .arg(eth->src[5], 2, 16, QLatin1Char('0'));
    switch (eth->type) {
    case 0x0806:
        /* ARP */
        dataStr << QString("Type: ARP (0x%1)").arg(eth->type, 4, 16, QLatin1Char('0'));
        dataStr.append(arp_parser(pkt_data));
        break;
    case 0x0800:
        /* IPv4 */
        dataStr << QString("Type: IPv4 (0x%1)").arg(eth->type, 4, 16, QLatin1Char('0'));
        //return analyze_ip((u_char*)pkt+14,data,npacket);
        break;
    case 0x86dd:
        /* IPv6 */
        dataStr << QString("Type: IPv6 (0x%1)").arg(eth->type, 4, 16, QLatin1Char('0'));
        //return analyze_ip6((u_char*)pkt+14,data,npacket);			=
        break;
    default:
        dataStr << QString("Type: 0x%1").arg(eth->type, 4, 16, QLatin1Char('0'));
        break;
    }
    qDebug()<<dataStr;
    return dataStr;
}

QStringList CapThread::arp_parser(const u_char *pkt_data)
{
    arp_header *arp;
    QStringList arpData;

    arp = (arp_header *)(pkt_data + 14);

    arp->ar_hw = ntohs(arp->ar_hw);
    arp->ar_op = ntohs(arp->ar_op);
    arp->ar_prot = ntohs(arp->ar_prot);

    /* ARP帧
     *  [硬件类型] [协议类型] [硬件地址长度] [协议地址长度] [   op  ]
     *  [2 Bytes] [2 Bytes] [ 1 Byte  ]  [ 1 Byte   ] [2 Bytes]
     *  [发送端MAC] [发送端IP] [接收方MAC] [接收方IP]
     *  [6 bytes ] [4 bytes] [6 bytes ] [4 bytes]
     */
    QString hwType = (arp->ar_hw == 0x1)
            ? "Hardware Type: Ethernet (0x1)"
            : QString("Hardware Type: 0x%1").arg(arp->ar_hw, 0, 16);
    QString protType;
    switch (arp->ar_prot) {
    case 0x0806:
        /* ARP */
        protType = "Protocol Type: ARP (0x0806)";
        break;
    case 0x0800:
        /* IPv4 */
        protType = "Protocol Type: IPv4 (0x0800)";
        break;
    case 0x86dd:
        /* IPv6 */
        protType = "Protocol Type: IPv6 (0x86dd)";
        break;
    default:
        protType = QString("Protocol Type: 0x%1").arg(arp->ar_prot, 4, 16, QLatin1Char('0'));
        break;
    }
    arpData << hwType << protType
            << QString("Hardware Size: %1").arg(arp->ar_hln, 0, 10)
            << QString("Protocol Size: %1").arg(arp->ar_pln, 0, 10)
            << ((arp->ar_op == 0x1)?QString("Opcode: request (1)"):QString("Opcode: response (2)"))
            << QString("Sender MAC address: %1:%2:%3:%4:%5:%6")
               .arg(arp->ar_srcmac[0], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_srcmac[1], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_srcmac[2], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_srcmac[3], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_srcmac[4], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_srcmac[5], 2, 16, QLatin1Char('0'))
            << QString("Sender IP address: %1.%2.%3.%4")
               .arg(arp->ar_srcip[0]).arg(arp->ar_srcip[1])
               .arg(arp->ar_srcip[2]).arg(arp->ar_srcip[3])
            << QString("Target MAC address: %1:%2:%3:%4:%5:%6")
               .arg(arp->ar_destmac[0], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_destmac[1], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_destmac[2], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_destmac[3], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_destmac[4], 2, 16, QLatin1Char('0'))
            .arg(arp->ar_destmac[5], 2, 16, QLatin1Char('0'))
            << QString("Target IP address: %1.%2.%3.%4")
               .arg(arp->ar_destip[0]).arg(arp->ar_destip[1])
               .arg(arp->ar_destip[2]).arg(arp->ar_destip[3]);
    return arpData;
}

QStringList CapThread::ip_parser(uint pktLen, const u_char *pkt_data)
{

}

u_int CapThread::ipConvertToInt(QString ip)
{
    QStringList strList = ip.split(".");
    QString uintStr;
    uintStr = QString("0x%1%2%3%4").arg(strList[0].toInt(), 2, 16, QLatin1Char('0'))
            .arg(strList[1].toInt(), 2, 16, QLatin1Char('0')).arg(strList[2].toInt(), 2, 16, QLatin1Char('0'))
            .arg(strList[3].toInt(), 2, 16, QLatin1Char('0'));
    qDebug()<<uintStr;
    return uintStr.toUInt();
}
