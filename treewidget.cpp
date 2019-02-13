#include "treewidget.h"

TreeWidget::TreeWidget(QWidget *parent) : QTreeWidget(parent)
{
    /* Set Header Invisiable */
    this->setHeaderHidden(true);
}

void TreeWidget::addNicInfo(DevInfo *devInfo)
{
    /* 设备描述(Description) */
    QTreeWidgetItem *rootNic = new QTreeWidgetItem(this,
                                                   QStringList(QString("Description: ") + (devInfo->description.isEmpty()?"Unknown Device":devInfo->description)));

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

    return {curItem->text(0).split(": ")[1].trimmed(), curItem->child(0)->text(0).split(": ")[1].trimmed()};
}
