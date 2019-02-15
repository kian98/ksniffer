#ifndef DEVINFO_H
#define DEVINFO_H

#include <QString>
#include <QVector>

struct Address {
    /* IP Address Family Name */
    QString saFamily = "";

    /* IP Address */
    QString ipAddr = "";

    /* Netmask */
    QString netmask = "";

    /* Broadcast Address */
    QString broadAddr = "";

    /* Destination Address */
    QString dstAddr = "";
};

struct DevInfo {
    /* 设备名(Name) */
    QString name = "";

    /* 设备描述(Description) */
    QString description = "";

    /* Loopback Address*/
    QString loopbackAddr = "";

    /* IP Address */
    QVector<Address *> ipAddresses;
};

enum PROT{
    TCP, UDP, IPv4, IPv6, ICMP, ARP, HTTP, OTHER
};

struct DataTableItem {
    /* 时间戳 */
    QString timeStamp = "";

    /* 协议类型 */
    int protocol = OTHER;

    /* 源地址 */
    QString source = "";

    /* 目的地址 */
    QString dest = "";

    /* 数据包长度 */
    uint len;

    /* 详细信息 */
    QString info = "";
};

#endif // DEVINFO_H
