#include "datatable.h"
#include <QHeaderView>
#include <QDebug>

DataTable::DataTable(QWidget *parent) : QTableWidget(parent)
{
    /* Header 格式设置 */
    this->horizontalHeader()->setVisible(true);
    this->setColumnCount(6);
    QStringList tableHeader;
    tableHeader << "Time" << "Protocol" << "Source"
                << "Destination" << "Length" << "Info";
    this->setHorizontalHeaderLabels(tableHeader);
    QFont headerFont;
    headerFont.setBold(true);
    this->horizontalHeader()->setFont(headerFont);

    /* 设置整行选中 */
    this->setSelectionBehavior ( QAbstractItemView::SelectRows);
    this->setSelectionMode(QAbstractItemView::SingleSelection);

    /* 设置不可编辑 */
    this->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /* Header 自动填充表 */
    this->horizontalHeader()->setStretchLastSection(true);

    /* 自动调整列宽 */
    this->horizontalHeader()->setSectionResizeMode(SOURCE, QHeaderView::ResizeToContents);
    this->horizontalHeader()->setSectionResizeMode(DESTINATION, QHeaderView::ResizeToContents);
}

void DataTable::addData(QStringList data, uint pktlen, const uchar *pkt_data)
{
    int rowIndex;
    QString proto, timestamp, len, destAddr, sourceAddr, info;

    /* Ethernet II      [3]
     *    - ARP         [9]
     *    - IPv4        [11]
     *    - IPv6        [9]
     *        - TCP     [10]
     *        - UDP     [5]
     *        - ICMP    [6]
     *        - ICMPv6  [4]
     * Protocol Name    [1]
     * Timestamp        [1]
     * Packet Length    [1]
     */

    proto = *(data.end() - 3);
    timestamp = *(data.end() - 2);
    len = *(data.end()-1);
    if(proto == "ARP"){
        sourceAddr = data[ 3 + 5].split(": ")[1];
        destAddr = data[ 3 + 7].split(": ")[1];
        if(data[ 3 + 7 ].split(": ")[1] == "00:00:00:00:00:00"){
            info = QString("Who has %1? Tell %2").arg(data[ 3 + 6].split(": ")[1]).arg(data[ 3 + 8].split(": ")[1]);
        }else {
            info = QString("%1 is at %2").arg(data[ 3 + 6].split(": ")[1]).arg(data[ 3 + 5].split(": ")[1]);
        }
    }else if (proto == "TCP" || proto == "HTTP" || proto == "UDP" || proto == "ICMP" || proto == "IPv4") {
        sourceAddr = data[ 3 + 10 - 1].split(": ")[1];
        destAddr = data[ 3 + 11 - 1].split(": ")[1];
        if (proto == "ICMP"){
            info = data[ 3 + 12 - 1];
        }else if(proto != "IPv4"){
            info = QString("Port: %1 → Port: %2 ").arg(data[ 3 + 11 + 1 - 1].split(": ")[1]).arg(data[ 3 + 11 + 2 - 1].split(": ")[1]);
            if(proto == "HTTP"){
                QString httpType = (*(data.end() - 4)).split(": ")[1];
                if(httpType != "Unknown")
                    info.append("  Type: " + httpType);
            }
        }else {
            info = data[3+8-1];
        }

    }else if (proto == "ICMPv6" || proto == "TCPv6" || proto == "UDPv6" || proto == "IPv6") {
        sourceAddr = data[ 3 + 8 - 1].split(": ")[1];
        destAddr = data[ 3 + 9 - 1].split(": ")[1];
    }else if(proto == "Ethernet II"){
        sourceAddr = data[ 2 - 1].split(": ")[1];
        destAddr = data[ 1 - 1].split(": ")[1];
        info = data[ 3 - 1];
    }

    rowIndex = this->rowCount();
    this->insertRow(rowIndex);
    this->setItem(rowIndex, TIME, new QTableWidgetItem(timestamp));
    this->setItem(rowIndex, PROTOCOL, new QTableWidgetItem(proto));
    this->setItem(rowIndex, SOURCE, new QTableWidgetItem(sourceAddr));
    this->setItem(rowIndex, DESTINATION, new QTableWidgetItem(destAddr));
    this->setItem(rowIndex, LENGTH, new QTableWidgetItem(len));
    this->setItem(rowIndex, INFO, new QTableWidgetItem(info));

    /* 设置居中 */
    for(int i = 0; i < 6;i++){
        this->item(rowIndex, i)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    }
}
