#ifndef TREEWIDGET_H
#define TREEWIDGET_H

#include <QTreeWidget>
#include "devinfo.h"

class TreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    explicit TreeWidget(QWidget *parent = nullptr);
    void addNicInfo(DevInfo *);
    QStringList getCurrentNicName();

signals:

public slots:
};

#endif // TREEWIDGET_H
