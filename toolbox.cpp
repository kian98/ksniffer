#include "toolbox.h"
#include "ui_toolbox.h"

ToolBox::ToolBox(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ToolBox)
{
    this->setWindowFlags(Qt::Tool | Qt::WindowStaysOnTopHint);
    ui->setupUi(this);

    /* 设置按钮图标 */
    ui->arpBtn->setIcon(QIcon(":/icon/res/arpspoof.png"));
    ui->icmpBtn->setIcon(QIcon(":/icon/res/icmp.png"));

    /* 点击出现工具窗口 */
    connect(ui->arpBtn, &QPushButton::clicked, [=](){
        arpSpoof= new ArpSpoof(nullptr, nicName);
        arpSpoof->show();
    });
    connect(ui->icmpBtn, &QPushButton::clicked, [=](){
        icmpFlood= new IcmpFlood(nullptr, nicName, nicIP);
        icmpFlood->show();
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
    if(icmpFlood != nullptr){
        icmpFlood->close();
    }
    if(arpSpoof != nullptr){
        arpSpoof->close();
    }
}


