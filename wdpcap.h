#ifndef WDPCAP_H
#define WDPCAP_H

//添加需要的头文件
#define WPCAP
#define HAVE_REMOTE

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <ws2tcpip.h>
    #include <winsock.h>
#endif

#include "pcap.h"

#endif // WDPCAP_H
