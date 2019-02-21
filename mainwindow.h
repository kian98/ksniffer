#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include <QString>
#include "wdpcap.h"
#include "devinfo.h"
#include "capthread.h"

namespace Ui {
class MainWindow;
}

struct pktData {
    uint len;
    const u_char *pkt_data;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    QVector<DevInfo *> getNicInfo();
    //int tcp, udp, http, icmp, arp, ipv4, ipv6, other;
    int pktCount[8] = {0, 0, 0, 0, 0, 0, 0, 0};

private:
    Ui::MainWindow *ui;
    CapThread *capThread = nullptr;
    QString selectedNicName;
    QVector<QStringList> pktVector;
    QVector<pktData*> pktRaw;

    DevInfo* ifget(pcap_if_t *d);
    char * iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *Address, int addrlen);

signals:
    void detailInfoRequest(int index);

public slots:
    void saveData(QStringList data, uint len,const uchar *pkt_data);
};

#endif // MAINWINDOW_H
