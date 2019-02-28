#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include <QString>
#include "wdpcap.h"
#include "devinfo.h"
#include "capthread.h"
#include "toolbox.h"

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

    QString selectedNicName;

private:
    Ui::MainWindow *ui;
    CapThread *capThread = nullptr;
    QVector<QStringList> pktVector;
    QVector<pktData*> pktRaw;
    QString customFilter = "";

    DevInfo* ifget(pcap_if_t *d);
    char * iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *Address, int addrlen);
    ToolBox* toolbox = nullptr;
    QTimer *pktCountSender;
    int m_sendCount;

    void closeEvent(QCloseEvent *event);

signals:
    void detailInfoRequest(int index);
    void sendPktCount(int time, int pCount[]);
    void clearIOChart();

public slots:
    void saveData(QStringList data, uint len,const uchar *pkt_data);
    void setFilter(QString f);
    void popWarningBox(QString title, QString text);
};

#endif // MAINWINDOW_H
