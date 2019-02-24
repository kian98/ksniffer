#ifndef TOOLBOX_H
#define TOOLBOX_H

#include <QDialog>
#include "arpspoof.h"

namespace Ui {
class ToolBox;
}

class ToolBox : public QDialog
{
    Q_OBJECT

public:
    explicit ToolBox(QWidget *parent = nullptr);
    ~ToolBox();

    void setNicName(QString name);

private:
    Ui::ToolBox *ui;
    ArpSpoof* arpSpoof = nullptr;

    QString nicName;

    void closeEvent(QCloseEvent *event);
};

#endif // TOOLBOX_H
