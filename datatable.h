#ifndef DATATABLE_H
#define DATATABLE_H

#include <QTableWidget>
#include "devinfo.h"

class DataTable : public QTableWidget
{
    Q_OBJECT
public:
    enum DataStruct{
        TIME, PROTOCOL, SOURCE, DESTINATION, LENGTH, INFO
    };
    QString ProtName[8] = {
        "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ARP", "HTTP", "OTHER"
    };

    explicit DataTable(QWidget *parent = nullptr);
    void addData(QStringList data, uint pktlen, const uchar *pkt_data);

signals:

public slots:
};

#endif // DATATABLE_H
