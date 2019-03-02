#include "toolbox.h"
#include "ui_toolbox.h"
#include "mainwindow.h"

#include <QDebug>

ToolBox::ToolBox(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ToolBox)
{
    this->setWindowFlags(Qt::Tool | Qt::CustomizeWindowHint | Qt::WindowTitleHint);
    ui->setupUi(this);

    /* 设置按钮图标 */
    ui->arpBtn->setIcon(QIcon(":/icon/res/arpspoof.png"));
    ui->icmpBtn->setIcon(QIcon(":/icon/res/icmp.png"));
    ui->ioBtn->setIcon(QIcon(":/icon/res/ioStat.png"));
    ui->scanBtn->setIcon(QIcon(":/icon/res/scan.png"));

    /* 点击出现工具窗口 */
    connect(ui->arpBtn, &QPushButton::clicked, [=](){
        arpSpoof= new ArpSpoof(nullptr, nicName);
        arpSpoof->show();
        this->arpClosed = false;
        connect(arpSpoof, &ArpSpoof::beClosed, [=](){
            this->arpClosed = true;
        });
    });
    connect(ui->icmpBtn, &QPushButton::clicked, [=](){
        icmpFlood= new IcmpFlood(nullptr, nicName, nicIP);
        icmpFlood->show();
        this->icmpClosed = false;
        connect(icmpFlood, &IcmpFlood::beClosed, [=](){
            this->icmpClosed = true;
        });
    });

    connect(ui->scanBtn, &QPushButton::clicked, [=](){
        lanScan= new LanScan(nullptr, nicName, nicIP);
        lanScan->show();
        this->scanClosed = false;
        connect(lanScan, &LanScan::beClosed, [=](){
            this->icmpClosed = true;
        });
    });

    ioStats= new IOStats;
    this->ioClosed = false;
    connect(this, &ToolBox::passPktCount, ioStats, &IOStats::refreshChart);
    connect(this, &ToolBox::passClearSignal, ioStats, &IOStats::clearChart);

    connect(ui->ioBtn, &QPushButton::clicked, [=](){
        ioStats->show();
        ioStats->isCustomized = false;
    });


}

ToolBox::~ToolBox()
{
    delete ui;
}

void ToolBox::setNicInfo(QString name, QString ip)
{
    this->nicName = name;
    this->nicIP = ip;
}

void ToolBox::closeEvent(QCloseEvent *event)
{
    /* 当指针不为空，即窗口从未打开过，没有初始化，
     * 或者窗口已经被用户关闭，自动销毁，则不需要再关闭
     */
    if(arpSpoof != nullptr && !this->arpClosed){
        arpSpoof->close();
    }
    if(icmpFlood != nullptr && !this->icmpClosed){
        icmpFlood->close();
    }
    if(lanScan != nullptr && !this->scanClosed){
        lanScan->close();
    }
    ioStats->close();
}

void ToolBox::hideEvent(QHideEvent *event)
{
    if(arpSpoof != nullptr && !this->arpClosed){
        arpSpoof->close();
    }
    if(icmpFlood != nullptr && !this->icmpClosed){
        icmpFlood->close();
    }
    ioStats->clearChart();
    ioStats->hide();
}
