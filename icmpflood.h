#ifndef ICMPFLOOD_H
#define ICMPFLOOD_H

#include <QWidget>
#include <QButtonGroup>
#include "wdpcap.h"

namespace Ui {
class IcmpFlood;
}

class IcmpFlood : public QWidget
{
    Q_OBJECT

public:
    explicit IcmpFlood(QWidget *parent = nullptr, QString nicName = "", QString nicIP = "");
    ~IcmpFlood();

private:
    Ui::IcmpFlood *ui;
    QButtonGroup *btnGroup;
    QButtonGroup *rateGroup;
    bool keepSend;
    int mode = 0;
    QString nicName;
    QString nicIP;
    pcap_t *fp = nullptr;

    void directIcmpFlood();
    void fakeIpIcmpFlood();
signals:
    void sendText(QString text);

public slots:
    void onRadioBtnChecked();
    void addText(QString text);
};

#endif // ICMPFLOOD_H
