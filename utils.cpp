#include "utils.h"

bool Utils::getNicMAC(QString nicIP, u_char targetMAC[6])
{
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG outBufLen = 0;
    DWORD dwRetVal = 0;
    int i;
    GetAdaptersAddresses(AF_UNSPEC,0, nullptr, pAddresses,&outBufLen);
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if ((dwRetVal = GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST,nullptr,pAddresses,&outBufLen)) == NO_ERROR) {
        while (pAddresses) {
            for(int j = 0;j<6;j++){
                targetMAC[j] = pAddresses->PhysicalAddress[j];
            }

            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAddresses->FirstUnicastAddress;

            for (i = 0; pUnicast != nullptr; i++)
            {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                {
                    sockaddr_in *sa_in = (sockaddr_in *)pUnicast->Address.lpSockaddr;
                    QString ip = QString("%1.%2.%3.%4").arg(sa_in->sin_addr.S_un.S_un_b.s_b1)
                              .arg(sa_in->sin_addr.S_un.S_un_b.s_b2)
                              .arg(sa_in->sin_addr.S_un.S_un_b.s_b3)
                              .arg(sa_in->sin_addr.S_un.S_un_b.s_b4);
                    if(ip == nicIP){
                        return true;
                    }
                }
                else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                {
                    sockaddr_in6 *sa_in6 = (sockaddr_in6 *)pUnicast->Address.lpSockaddr;
                }
                pUnicast = pUnicast->Next;
            }
            pAddresses = pAddresses->Next;
        }
    }
    else {
        LPVOID lpMsgBuf;
        qDebug("Call to GetAdaptersAddresses failed.\n");
        if (FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr,
                    dwRetVal,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPTSTR) &lpMsgBuf,
                    0,
                    nullptr )) {
            qDebug("\tError: %s", lpMsgBuf);
        }
        LocalFree( lpMsgBuf );
    }
    free(pAddresses);
    return false;
}

u_short Utils::get_ip_checksum(char* ip_hdr)
{
    char* ptr_data = ip_hdr;
    u_long  tmp = 0;
    u_long  sum = 0;
    for (int i=0; i<20; i+=2)
    {
        tmp += (u_char)ptr_data[i] << 8;
        tmp += (u_char)ptr_data[i+1];
        sum += tmp;
        tmp = 0;
    }
    u_short lWord = sum & 0x0000FFFF;
    u_short hWord = sum >> 16;
    u_short checksum = lWord + hWord;
    checksum = ~checksum;
    return checksum;
}

ushort Utils::get_icmp_checksum(ushort *buffer,int size)
{
    unsigned long cksum=0;
    //将数据以字为单位累加到CKSUM中
    while(size>1)
    {
        cksum+=*buffer++;
        size-=sizeof(ushort);
    }
    //如果为奇数，将最后一个字节扩展到双字，再累加到cksum中
    if(size)
    {
        cksum+=*(uchar *)buffer;
    }
    //将cksum的高16位和低16位相加，取反后得到校验和
    cksum=(cksum>>16)+(cksum&0xffff);
    cksum+=(cksum>>16);
    return static_cast<ushort>(~cksum);

}

bool Utils::IcmpGenerator(u_char mac_src[6], u_char ip_src[4], u_char mac_dest[6], u_char ip_dest[4], u_char packet[42])
{
    ushort id = 0x0000;

    /* 设置以太网帧 */
    eth_header eth;

    memcpy(&eth.src[0], &mac_src[0], 6);
    memcpy(&eth.dest[0], &mac_dest[0], 6);

    eth.type = htons(0x0800);
    memcpy(packet, &eth, sizeof (eth));

    /* IPv4 */
    ip_header ipv4;
    ipv4.ihl = 5;ipv4.version = 4;
    ipv4.tos = 0x00;ipv4.tlen = htons(28);
    ipv4.id = htons(id);ipv4.frag_off = 0x0000;
    ipv4.ttl = 64;ipv4.proto = 1;
    ipv4.check = 0;

    memcpy(&ipv4.saddr[0], &ip_src[0], 4);
    memcpy(&ipv4.daddr[0], &ip_dest[0], 4);

    /* 计算IPv4校验和 */
    ipv4.check = htons(get_ip_checksum((char*)&ipv4));

    memcpy(&packet[14], &ipv4, 20);

    /* ICMP头部 */
    icmp_header icmp;
    icmp.type = 0x08;
    icmp.code = 0;
    icmp.checksum = 0;
    icmp.id = htons(0x0001);
    icmp.seq = htons(id);

    icmp.checksum = get_icmp_checksum((ushort*)&icmp, sizeof(icmp));

    memcpy(&packet[34], &icmp, 8);
    return true;
}
