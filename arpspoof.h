#ifndef ARPSPOOF_H
#define ARPSPOOF_H

#include <QWidget>
#include "wdpcap.h"

namespace Ui {
class ArpSpoof;
}

class ArpSpoof : public QWidget
{
    Q_OBJECT

public:
    explicit ArpSpoof(QWidget *parent = nullptr, QString nicName = "");
    ~ArpSpoof();

private:
    Ui::ArpSpoof *ui;
    QString nicName;
    pcap_t *fp = nullptr;
    bool keepSend;
    void closeEvent(QCloseEvent *event);

    void arpSpoofing(QString targetIP, QString targetMAC, QString spoofIP, QString spoofMAC);

signals:
    void beClosed();
    void sendText(QString text);

public slots:
    void addText(QString text);
};

#endif // ARPSPOOF_H
