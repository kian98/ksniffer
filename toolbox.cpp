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

    /* 点击出现 ARP Spoofing 窗口 */
    connect(ui->arpBtn, &QPushButton::clicked, [=](){
        arpSpoof= new ArpSpoof(nullptr, nicName);
        arpSpoof->show();
    });
}

ToolBox::~ToolBox()
{
    delete ui;
}

void ToolBox::setNicName(QString name)
{
    this->nicName = name;
}

void ToolBox::closeEvent(QCloseEvent *event)
{
    if(arpSpoof != nullptr){
        arpSpoof->close();
    }
}


