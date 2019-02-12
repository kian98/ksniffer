#ifndef DEVINFO_H
#define DEVINFO_H

#include <QString>
#include <QVector>

struct address {
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
    QVector<address *> ipAddresses;
};

#endif // DEVINFO_H
