#ifndef UTILS_H
#define UTILS_H

#include <QDebug>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "wdpcap.h"
#include "capthread.h"

class Utils
{
public:
    static bool getNicMAC(QString nicIP, u_char targetMAC[6]);
    static u_short get_ip_checksum(char* ip_hdr);
    static ushort get_icmp_checksum(ushort *buffer,int size);
    static bool IcmpGenerator(u_char mac_src[6], u_char ip_src[4], u_char mac_dest[6], u_char ip_dest[4], u_char packet[42]);
};

#endif // UTILS_H
