#include "mainwindow.h"
#include <QApplication>
#include "wdpcap.h"
#include <QDebug>

// 函数原型
void get_all_adapter_info();
void ifprint(pcap_if_t *d);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    //for test configuratiojn
    get_all_adapter_info();

    return a.exec();
}

void get_all_adapter_info()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    char source[PCAP_ERRBUF_SIZE+1];

    qDebug("Enter the device you want to list:\n"
              "rpcap://              ==> lists interfaces in the local machine\n"
              "rpcap://hostname:port ==> lists interfaces in a remote machine\n"
              "                          (rpcapd daemon must be up and running\n"
              "                           and it must accept 'null' authentication)\n"
              "file://foldername     ==> lists all pcap files in the give folder\n\n"
              "Enter your choice: ");

    //  "rpcap://              ==> lists interfaces in the local machine\n"
    QString str_PCAP_SRC_IF_STRING = PCAP_SRC_IF_STRING;
    QByteArray string_array = str_PCAP_SRC_IF_STRING.toLocal8Bit();
    char* char_PCAP_SRC_IF_STRING = string_array.data();
    source[PCAP_ERRBUF_SIZE] = '\0';

    /* 获得接口列表 */
    if (pcap_findalldevs_ex(char_PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1)
    {
      fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
      exit(1);
    }

    /* 扫描列表并打印每一项 */
    for(d=alldevs;d;d=d->next)
    {
      ifprint(d);
    }

    pcap_freealldevs(alldevs);
}

/* 打印所有可用信息 */
void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];

  /* 设备名(Name) */
  qDebug("%s",d->name);

  /* 设备描述(Description) */
  if (d->description)
    qDebug("\tDescription: %s",d->description);

  /* Loopback Address*/
  qDebug("\tLoopback: %s",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    qDebug("\tAddress Family: #%d",a->addr->sa_family);

    switch(a->addr->sa_family)
    {
      case AF_INET:
        qDebug("\tAddress Family Name: AF_INET");
        if (a->addr)
          qDebug("\tAddress: %s",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          qDebug("\tNetmask: %s",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          qDebug("\tBroadcast Address: %s",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          qDebug("\tDestination Address: %s",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;

      case AF_INET6:
        qDebug("\tAddress Family Name: AF_INET6");
        if (a->addr)
          qDebug("\tAddress: %s", ip6tos(a->addr, ip6str, sizeof(ip6str)));
       break;

      default:
        qDebug("\tAddress Family Name: Unknown");
        break;
    }
  }
}


/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
//input 为二进制数（十六进制），一共4*8=32位
//直接转为char类型即可，无符号char类型占2个字节，即8位，正好为一个点十进制表示的IP地址的一部分
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = reinterpret_cast<u_char*>(&in);
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif


    if(getnameinfo(sockaddr,
        sockaddrlen,
        address,
        static_cast<DWORD>(addrlen),
        nullptr,
        0,
        NI_NUMERICHOST) != 0) address = nullptr;

    return address;
}

