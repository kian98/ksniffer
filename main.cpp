#include <QApplication>
#include "mainwindow.h"

#include "commonhelper.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    CommonHelper::setStyle(":/stylesheet/res/ksnifferStyleSheet.qss");
    MainWindow w;
    w.show();
    return a.exec();
}
