#include "capthread.h"
#include <QMessageBox>
#include <QDebug>

CapThread::CapThread(QMainWindow *w, DevInfo* nic)
{
    this->nic = nic;
    this->w = w;
}

CapThread::~CapThread()
{
    pcap_close(adhandle);
    requestInterruption();
    quit();
    wait();
}

void CapThread::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask = 0xffffff;
    char packet_filter[] = "";
    struct bpf_program fcode;
    int res = 0;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

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
        // TODO
        // MessageBox needs signals and slots
        //QMessageBox::critical(w, "Not Supported", "Unable to open the adapter");
    }

    /* 检查数据链路层，为了简单，只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        //QMessageBox::critical(w, "Ethernet Only", "This program works only on Ethernet networks.");
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
        //QMessageBox::critical(w, "Compile Error", "Unable to compile the packet filter.");
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        //QMessageBox::critical(w, "Filter Error", "Error setting the filter.");
    }

    /* 获取数据包 */
    while(!isInterruptionRequested() && (res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

        if(res == 0)
            /* 超时时间到 */
            continue;

        /* 申请存储内存空间 */
        pktData *data = (pktData *)malloc(sizeof (pktData));
        memset(data, 0, sizeof (pktData));

        if(data == nullptr){
            //QMessageBox::critical(w, "Error", "Memory Full");
            break;
        }
        data->header = header;
        data->pkt_data = pkt_data;
        pktVector.push_back(data);

        packet_handler(nullptr, pktVector.back()->header, pktVector.back()->pkt_data);
    }

    if(res == -1){
        qDebug("Error reading the packets: %s\n", pcap_geterr(adhandle));
        //QMessageBox::critical(w, "Error", "Error reading the packets");
    }
}

/* 用于解析，当收到每一个数据包时会调用 */
void CapThread::packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* 数据包的时间戳和长度 */
    qDebug("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
    QString timeStamp = QString(timestr) + "." + QString::number(header->ts.tv_usec).mid(0,2);

    /* 解析结果 */
    auto data = ethernet_parser(header->len, pkt_data);
    data << timeStamp << QString("%1").arg(header->len, 0, 10);

    qDebug()<<data;
    emit sendTableData(data);
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
        dataStr.append(ip_parser(pktLen, pkt_data));
        break;
    case 0x86dd:
        /* IPv6 */
        dataStr << QString("Type: IPv6 (0x%1)").arg(eth->type, 4, 16, QLatin1Char('0'));
        dataStr.append(ip6_parser(pktLen, pkt_data));
        break;
    default:
        dataStr << QString("Type: 0x%1").arg(eth->type, 4, 16, QLatin1Char('0'));
        dataStr.append("Ethernet II");
    }
    return dataStr;
}

QStringList CapThread::arp_parser(const u_char *pkt_data)
{
    arp_header *arp;
    QStringList arpData;

    arp = (arp_header *)(pkt_data + IP_HEADER_OFFSET);

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
            .arg(arp->ar_destip[2]).arg(arp->ar_destip[3])
            << "ARP";
    return arpData;
}

QStringList CapThread::ip_parser(uint pktLen, const u_char *pkt_data)
{
    ip_header *ipv4;
    QStringList ipData;

    ipv4 = (ip_header *)(pkt_data + IP_HEADER_OFFSET);
    ipv4->tlen = ntohs(ipv4->tlen);

    QString prot;
    QString defaultProto;
    QStringList nextStrList;
    uint offset = ipv4->ihl*4;
    switch (ipv4->proto) {
    case 1:
        prot = "ICMP";
        nextStrList.append(icmp_parser(pktLen, offset, pkt_data));
        break;
    case 6:
        prot = "TCP";
        nextStrList.append(tcp_parser(pktLen, offset, pkt_data, 4));
        break;
    case 17:
        prot = "UDP";
        nextStrList.append(udp_parser(pktLen, offset, pkt_data, 4));
        break;
    default:
        defaultProto = "IPv4";
    }

    ipData<<QString("Version: %1").arg(ipv4->version)
         << QString("Header Length: %1 bytes (%2)").arg(ipv4->ihl * 4).arg(ipv4->ihl)
         << QString("Differentiated Services Field: 0x%1").arg(ipv4->tos, 2, 16, QLatin1Char('0'))
         << QString("Total Length: %1").arg(ipv4->tlen)
         << QString("Identification: 0x%1").arg(ipv4->ihl, 4, 16, QLatin1Char('0'))
         << QString("Flags: 0x%1").arg(ipv4->frag_off, 4, 16, QLatin1Char('0'))
         << QString("Time to live: %1").arg(ipv4->ttl, 0)
         << QString("Protocol: %1 (%2)").arg(prot).arg(ipv4->proto)
         << QString("Header checksum: 0x%1").arg(ipv4->check, 4, 16, QLatin1Char('0'))
         << QString("Source: %1.%2.%3.%4")
            .arg(ipv4->saddr[0]).arg(ipv4->saddr[1])
            .arg(ipv4->saddr[2]).arg(ipv4->saddr[3])
            << QString("Destination: %1.%2.%3.%4")
               .arg(ipv4->daddr[0]).arg(ipv4->daddr[1])
            .arg(ipv4->daddr[2]).arg(ipv4->daddr[3]);
    ipData.append(nextStrList);
    if(defaultProto.size()!=0){
        ipData.append(defaultProto);
    }
    return ipData;
}

QStringList CapThread::ip6_parser(uint pktLen, const u_char *pkt_data)
{
    ip6_header *ipv6;
    QStringList ip6Data;

    ipv6 = (ip6_header *)(pkt_data + IP_HEADER_OFFSET);
    ipv6->plen = ntohs(ipv6->plen);

    QString nextHeader;
    QString defaultProto;
    QStringList nextStrList;
    switch (ipv6->nh) {
    case 0x3a:
        nextHeader = "ICMPv6";
        nextStrList.append(icmp6_parser(pktLen, 40, pkt_data));
        break;
    case 0x06:
        nextHeader = "TCP";
        nextStrList.append(tcp_parser(pktLen, 40, pkt_data, 6));
        break;
    case 0x11:
        nextHeader = "UDP";
        nextStrList.append(udp_parser(pktLen, 40, pkt_data, 6));
        break;
    default :
        defaultProto = "IPv6";
    }

    ip6Data << QString("Version: %1").arg(ipv6->version)
            << QString("Traffic Class: 0x%1").arg(ipv6->flowtype, 2, 16, QLatin1Char('0'))
            << QString("Flow Label: %1").arg(ipv6->flowid, 5, 16, QLatin1Char('0'))
            << QString("Payload Length: %1").arg(ipv6->plen)
            << QString("Flow label: %1").arg(ipv6->flowid, 5, 16, QLatin1Char('0'))
            << nextHeader
            << QString("Hop Limit: %1").arg(ipv6->hlim)
            << QString("Source: %1:%2:%3:%4:%5:%6:%7:%8")
               .arg(ipv6->saddr[0], 4, 16, QLatin1Char('0')).arg(ipv6->saddr[1], 4, 16, QLatin1Char('0'))
            .arg(ipv6->saddr[2], 4, 16, QLatin1Char('0')).arg(ipv6->saddr[3], 4, 16, QLatin1Char('0'))
            .arg(ipv6->saddr[4], 4, 16, QLatin1Char('0')).arg(ipv6->saddr[5], 4, 16, QLatin1Char('0'))
            .arg(ipv6->saddr[5], 4, 16, QLatin1Char('0')).arg(ipv6->saddr[7], 4, 16, QLatin1Char('0'))
            << QString("Destination: %1:%2:%3:%4:%5:%6:%7:%8")
               .arg(ipv6->daddr[0], 4, 16, QLatin1Char('0')).arg(ipv6->daddr[1], 4, 16, QLatin1Char('0'))
            .arg(ipv6->daddr[2], 4, 16, QLatin1Char('0')).arg(ipv6->daddr[3], 4, 16, QLatin1Char('0'))
            .arg(ipv6->daddr[4], 4, 16, QLatin1Char('0')).arg(ipv6->daddr[5], 4, 16, QLatin1Char('0'))
            .arg(ipv6->daddr[5], 4, 16, QLatin1Char('0')).arg(ipv6->daddr[7], 4, 16, QLatin1Char('0'));
    ip6Data.append(nextStrList);

    if(defaultProto.size()!=0){
        ip6Data.append(defaultProto);
    }
    return ip6Data;
}

QStringList CapThread::icmp_parser(uint pktLen, uint offset,const u_char *pkt_data)
{
    icmp_header *icmp;
    QStringList icmpData;

    icmp = (icmp_header *)(pkt_data + (IP_HEADER_OFFSET + offset));
    icmp->checksum = ntohs(icmp->checksum);
    icmp->id = ntohs(icmp->id);
    uint dataLength = pktLen - 14 - offset - 8;

    icmpData << QString("Type: %1").arg(icmp->type)
             << QString("Code: %1").arg(icmp->code)
             << QString("Checksum: 0x%1").arg(icmp->checksum, 4, 16, QLatin1Char('0'))
             << QString("Identifier: %1 (0x%2)").arg(icmp->id).arg(icmp->id, 4, 16, QLatin1Char('0'))
             << QString("Sequence number: %1 (0x%2)").arg(icmp->seq).arg(icmp->seq, 4, 16, QLatin1Char('0'))
             << QString("Data (%1 Bytes)").arg(dataLength)
             << "ICMP";
    return icmpData;
}

QStringList CapThread::icmp6_parser(uint pktLen, uint offset, const u_char *pkt_data)
{
    icmp6_header *icmp6;
    QStringList icmp6Data;
    QString type;

    icmp6 = (icmp6_header *)(pkt_data + (IP_HEADER_OFFSET + offset));
    icmp6->checksum = ntohs(icmp6->checksum);
    uint dataLength = pktLen - 14 - offset - 8;
    if(icmp6->type == 0){
        type = "Echo (ping) Reply";
    }else if(icmp6->type == 8){
        type = "Echo (ping) Request";
    }

    icmp6Data << QString("Type: %1 " + type).arg(icmp6->type)
              << QString("Code: %1").arg(icmp6->code)
              << QString("Checksum: 0x%1").arg(icmp6->checksum, 4, 16, QLatin1Char('0'))
              << QString("Data (%1 Bytes)").arg(dataLength)
              << "ICMPv6";
    return icmp6Data;
}

QStringList CapThread::tcp_parser(uint pktLen, uint offset, const u_char *pkt_data, int type)
{
    tcp_header *tcp;
    uint headerLen;
    QString flags;
    QStringList tcpData;
    QStringList nextStrList;
    uint dataLength;

    tcp = (tcp_header *)(pkt_data + (IP_HEADER_OFFSET + offset));
    tcp->sport = ntohs(tcp->sport);
    tcp->dport = ntohs(tcp->dport);
    tcp->check = ntohs(tcp->check);

    headerLen = tcp->doff * 4;
    dataLength = pktLen - 14 - offset - headerLen;
    flags = QString("%1%2%3%4%5%6%7%8%9").arg(tcp->res1, 4, 2, QLatin1Char('0'))
            .arg(tcp->cwr, 1, 2).arg(tcp->ece, 1, 2).arg(tcp->urg, 1, 2).arg(tcp->ack, 1, 2)
            .arg(tcp->psh, 1, 2).arg(tcp->rst, 1, 2).arg(tcp->syn, 1, 2).arg(tcp->fin, 1, 2);

    if(tcp->dport == 80 || tcp->sport == 80){
        nextStrList = http_parser(pktLen, 14 + offset + headerLen, pkt_data, type);
    }

    /* TODO
     *  SEQ 和 ACK 大小端转换
     */

    tcpData << QString("Source Port: %1").arg(tcp->sport)
            << QString("Destination Port: %1").arg(tcp->dport)
            << QString("Sequence number: %1").arg(tcp->seq)
            << QString("Acknowledgment number: %1").arg(tcp->ack_seq)
            << QString("Header Length； %1").arg(headerLen)
            << QString("Flags: 0x%1 (%2)").arg(flags.toInt(nullptr, 2), 3, 16, QLatin1Char('0')).arg(flags.toInt(nullptr, 2), 12, 2, QLatin1Char('0'))
            << QString("Window size value: %1").arg(tcp->window)
            << QString("Checksum: 0x%1").arg(tcp->check, 4, 16, QLatin1Char('0'))
            << QString("Urgent point: %1").arg(tcp->urg_ptr)
            << QString("TCP payload (%1 Bytes)").arg(dataLength);
    if(!nextStrList.empty()){
        tcpData.append(nextStrList);
    } else {
        tcpData.append(((type == 4)?"TCP":"TCPv6"));
    }

    return tcpData;
}

QStringList CapThread::udp_parser(uint pktLen, uint offset, const u_char *pkt_data, int type)
{
    udp_header *udp;
    QStringList udpData;

    udp = (udp_header *)(pkt_data + (IP_HEADER_OFFSET + offset));

    udp->sport = ntohs( udp->sport );
    udp->dport = ntohs( udp->dport );
    udp->len = ntohs( udp->len );
    udp->crc = ntohs( udp->crc );

    udpData << QString("Source Port: %1").arg(udp->sport)
            << QString("Destination Port: %1").arg(udp->dport)
            << QString("Length: %1").arg(udp->len)
            << QString("Checksum: 0x%1").arg(udp->crc, 4, 16, QLatin1Char('0'))
            << QString("Data (%1 Bytes)").arg(udp->len - 8)
            << ((type == 4)?"UDP":"UDPv6");

    return udpData;
}

QStringList CapThread::http_parser(uint pktLen, uint offset,const u_char *pkt_data, int type)
{
    QStringList httpData;
    QString rawData;
    for(uint i = offset;i<pktLen;i++){
        rawData.append((QString("%1").arg(pkt_data[i], 0, 16)));
    }
    rawData = (QByteArray::fromHex(rawData.toLatin1()));
    if(rawData.mid(0,3) == "GET"){
        httpData << "Type: GET";
    }else if(rawData.mid(0,4) == "POST"){
        httpData << "Type: POST";
    }else {
        httpData << "Type: Unknown";
    }
    httpData.append((type == 4)?"HTTP":"HTTPv6");
    return httpData;
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
