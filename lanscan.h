#ifndef LANSCAN_H
#define LANSCAN_H

#include <QWidget>
#include "utils.h"

namespace Ui {
class LanScan;
}

class LanScan : public QWidget
{
    Q_OBJECT

public:
    explicit LanScan(QWidget *parent = nullptr, QString nicName= "", QString nicIP="");
    ~LanScan();

private:
    Ui::LanScan *ui;
    QString nicName;
    QString nicIP;
    u_char targetMAC[6];
    u_char ip_src[4];
    u_char ip_dest[4];
    pcap_t *fp = nullptr;
    pcap_t *adhandle;

    bool isInterrupted = false;
    bool isRunning = false;

    void icmpRequest(u_char mac_src[6], u_char ip_src[4],  u_char ip_dest[4], int musk);
    void icmpCapture();
    QStringList icmpAnalysis(const u_char *pkt_data);

    void showProgressDialog();
    void closeEvent(QCloseEvent *event);

signals:
    void interrupt();
    void scanFinish();
    void beClosed();
    void addDataRequest(QString info);
    void wrongMsg();

public slots:
    void popWarningBox();
};

#endif // LANSCAN_H
