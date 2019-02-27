#ifndef TOOLBOX_H
#define TOOLBOX_H

#include <QDialog>
#include "arpspoof.h"
#include "icmpflood.h"

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

    QString nicName;
    QString nicIP;
    bool arpClosed = false;
    bool icmpClosed = false;

    void closeEvent(QCloseEvent *event);
};

#endif // TOOLBOX_H
