#include "treewidget.h"
#include <QDebug>

TreeWidget::TreeWidget(QWidget *parent) : QTreeWidget(parent)
{
    /* Set Header Invisiable */
    this->setHeaderHidden(true);
}

void TreeWidget::addNicInfo(DevInfo *devInfo)
{
    /* 设备描述(Description) */
    QTreeWidgetItem *rootNic = new QTreeWidgetItem(
                this, QStringList(QString("Description: ") +
                                  (devInfo->description.isEmpty()?"Unknown Device":devInfo->description)));

    /* 设备名(Name) */
    QTreeWidgetItem *devName = new QTreeWidgetItem(rootNic, QStringList(QString("Name: ") + devInfo->name));
    rootNic->addChild(devName);

    /* Loopback Address*/
    QTreeWidgetItem *lbAddr = new QTreeWidgetItem(rootNic, QStringList(QString("Loopback: ") + devInfo->description));
    rootNic->addChild(lbAddr);

    /* IP addresses */
    for(auto a : devInfo->ipAddresses) {
        if( a->saFamily == "AF_INET")
        {
            QTreeWidgetItem *ipv4 = new QTreeWidgetItem(rootNic, QStringList(QString("Address Family Name: #2 ") + a->saFamily));
            rootNic->addChild(ipv4);
            ipv4->setExpanded(true);
            if (!a->ipAddr.isEmpty())
            {
                QTreeWidgetItem *ipv4Addr = new QTreeWidgetItem(ipv4, QStringList(QString("Address: ") + a->ipAddr));
                ipv4->addChild(ipv4Addr);
            }
            if (!a->netmask.isEmpty())
            {
                QTreeWidgetItem *netmask = new QTreeWidgetItem(ipv4, QStringList(QString("Netmask: ") + a->netmask));
                ipv4->addChild(netmask);
            }
            if (!a->broadAddr.isEmpty())
            {
                QTreeWidgetItem *broadAddr = new QTreeWidgetItem(ipv4, QStringList(QString("Broadcast Address: ") + a->broadAddr));
                ipv4->addChild(broadAddr);
            }
            if (!a->dstAddr.isEmpty())
            {
                QTreeWidgetItem *dstAddr = new QTreeWidgetItem(ipv4, QStringList(QString("Destination Address: ") + a->dstAddr));
                ipv4->addChild(dstAddr);
            }
        }else if (a->saFamily == "AF_INET6")
        {
            QTreeWidgetItem *ipv6 = new QTreeWidgetItem(rootNic, QStringList(QString("Address Family Name: #23 ") + a->saFamily));
            rootNic->addChild(ipv6);
            ipv6->setExpanded(true);
            if (!a->ipAddr.isEmpty())
            {
                QTreeWidgetItem *ipv6Addr = new QTreeWidgetItem(ipv6, QStringList(QString("Address: ") + a->ipAddr));
                ipv6->addChild(ipv6Addr);
            }
        }else
        {
            QTreeWidgetItem *unknown = new QTreeWidgetItem(rootNic, QStringList(QString("Address Family Name: Unknown")));
            rootNic->addChild(unknown);
        }
    }
}

QStringList TreeWidget::getCurrentNicName()
{
    QTreeWidgetItem* curItem = this->currentItem();
    while(curItem->parent()){
        curItem = curItem->parent();
    }

    auto devDesc = curItem->text(0).split(": ")[1].trimmed();
    auto devIP = curItem->child(curItem->childCount()-1)->child(0)->text(0).split(": ")[1].trimmed();
    auto devName = curItem->child(0)->text(0).split(": ")[1].trimmed();

    return {devDesc, devName, devIP};
}

void TreeWidget::addPacketInfo(QStringList data)
{
    this->clear();
    QString type = *(data.end()-3);

    QTreeWidgetItem *ethernet = new QTreeWidgetItem(this, QStringList("Ethernet II"));
    ethernet->setExpanded(true);
    for(int i = 0;i<3;i++){
        ethernet->addChild(new QTreeWidgetItem(ethernet, QStringList(data[i])));
    }
    if(type == "IPv4" || type == "TCP" || type == "UDP"
            || type == "HTTP" || type == "ICMP"){
        QTreeWidgetItem *ipv4 = new QTreeWidgetItem(this, QStringList("Internet Protocol Version 4"));
        ipv4->setExpanded(true);
        for(int i = 3;i < 11 + 3;i++){
            ipv4->addChild(new QTreeWidgetItem(ipv4, QStringList(data[i])));
        }

        if(type == "TCP" || type == "HTTP"){
            QTreeWidgetItem *tcp = new QTreeWidgetItem(this, QStringList("Transmission Control Protocol"));
            tcp->setExpanded(true);
            int i;
            for(i = 11+3;i < 11+3+10;i++){
                tcp->addChild(new QTreeWidgetItem(tcp, QStringList(data[i])));
            }
            if(type == "HTTP"){
                QTreeWidgetItem *http = new QTreeWidgetItem(this, QStringList("Hypertext Transfer Protocol"));
                http->addChild(new QTreeWidgetItem(http, QStringList(data[i])));
            }
        }else if (type == "UDP"){
            QTreeWidgetItem *udp = new QTreeWidgetItem(this, QStringList("User Datagram Protocol"));
            udp->setExpanded(true);
            for(int i = 11+3;i < 3+11+5;i++){
                udp->addChild(new QTreeWidgetItem(udp, QStringList(data[i])));
            }
        }else if (type == "ICMP"){
            QTreeWidgetItem *icmp = new QTreeWidgetItem(this, QStringList("Internet Control Message Protocol"));
            icmp->setExpanded(true);
            for(int i = 11+3;i < 3+11+6;i++){
                icmp->addChild(new QTreeWidgetItem(icmp, QStringList(data[i])));
            }
        }
    }else if(type == "IPv6" || type == "TCPv6" || type == "UDPv6"
             || type == "HTTPv6" || type == "ICMPv6"){
        QTreeWidgetItem *ipv6 = new QTreeWidgetItem(this, QStringList("Internet Protocol Version 6"));
        ipv6->setExpanded(true);
        for(int i = 3;i < 3+9;i++){
            ipv6->addChild(new QTreeWidgetItem(ipv6, QStringList(data[i])));
        }
        if(type == "TCPv6" || type == "HTTPv6"){
            QTreeWidgetItem *tcp6 = new QTreeWidgetItem(this, QStringList("Transmission Control Protocol"));
            tcp6->setExpanded(true);
            int i;
            for(i = 3+9;i < 3+9+10;i++){
                tcp6->addChild(new QTreeWidgetItem(tcp6, QStringList(data[i])));
            }
            if(type == "HTTPv6"){
                QTreeWidgetItem *http6 = new QTreeWidgetItem(this, QStringList("Hypertext Transfer Protocol"));
                http6->addChild(new QTreeWidgetItem(http6, QStringList(data[i])));
            }
        }else if (type == "UDPv6"){
            QTreeWidgetItem *udp6 = new QTreeWidgetItem(this, QStringList("User Datagram Protocol"));
            udp6->setExpanded(true);
            for(int i = 3+9;i < 3+9+5;i++){
                udp6->addChild(new QTreeWidgetItem(udp6, QStringList(data[i])));
            }
        }else if (type == "ICMPv6"){
            QTreeWidgetItem *icmp6 = new QTreeWidgetItem(this, QStringList("Internet Control Message Protocol"));
            icmp6->setExpanded(true);
            for(int i = 11+3;i < 3+9+4;i++){
                icmp6->addChild(new QTreeWidgetItem(icmp6, QStringList(data[i])));
            }
        }
    }else if(type == "ARP"){
        QTreeWidgetItem *arp = new QTreeWidgetItem(this, QStringList("Address Resolution Protocol"));
        arp->setExpanded(true);
        for(int i = 3;i < 3+9;i++){
            arp->addChild(new QTreeWidgetItem(arp, QStringList(data[i])));
        }
    }
}
