#ifndef TOOLBOX_H
#define TOOLBOX_H

#include <QDialog>
#include "arpspoof.h"
#include "icmpflood.h"
#include "iostats.h"
#include "lanscan.h"

namespace Ui {
class ToolBox;
}

class ToolBox : public QDialog
{
    Q_OBJECT

public:
    explicit ToolBox(QWidget *parent = nullptr);
    ~ToolBox();

    void setNicInfo(QString name, QString ip);

private:
    Ui::ToolBox *ui;
    ArpSpoof* arpSpoof = nullptr;
    IcmpFlood* icmpFlood = nullptr;
    IOStats* ioStats = nullptr;
    LanScan* lanScan = nullptr;

    QString nicName;
    QString nicIP;
    bool arpClosed = false;
    bool icmpClosed = false;
    bool ioClosed = false;
    bool scanClosed = false;

    void closeEvent(QCloseEvent *event);
    void hideEvent(QHideEvent *event);

signals:
    void passPktCount(int time, int pCount[]);
    void passClearSignal();

};

#endif // TOOLBOX_H
