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

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    QVector<DevInfo *> getNicInfo();

private:
    Ui::MainWindow *ui;
    CapThread *capThread = nullptr;

    DevInfo* ifget(pcap_if_t *d);
    char * iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *Address, int addrlen);
};

#endif // MAINWINDOW_H
