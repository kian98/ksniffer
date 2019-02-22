#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QStackedWidget>
#include <QMessageBox>
#include <QDebug>
#include "treewidget.h"

const int NIC_SELECT_SCENE = 0;
const int SNIFFER_SCENE = 1;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    /* 设置Stacke Widget初始索引页面 */
    ui->stackedWidget->setCurrentIndex(NIC_SELECT_SCENE);

    /******** 网卡选择界面 ********/
    /* 添加网卡设备数据 */
    auto nicInfo = getNicInfo();
    for (auto nif : nicInfo){
        ui->nicTree->addNicInfo(nif);
    }

    /* 选择网卡 */
    connect(ui->nicSelect, &QPushButton::clicked, [=](){
        QStringList curNicName = ui->nicTree->getCurrentNicName();
        ui->stackedWidget->setCurrentIndex(SNIFFER_SCENE);
        ui->nicDesc->setText(curNicName[0]);
        selectedNicName = curNicName[1];
        ui->pktSelect->setCurrentIndex(0);
    });

    /* 取消选择，退出 */
    connect(ui->nicCancel, &QPushButton::clicked, [=](){
        this->close();
    });

    /******** 数据监听界面 ********/
    /* 设置按钮 Enabled */
    ui->stopBtn->setEnabled(false);

    /* 下拉框不可编辑 */
    ui->pktSelect->setEditable(false);

    /* 设置下拉框 */
    ui->pktSelect->addItem("Default");
    ui->pktSelect->addItem("TCP");
    ui->pktSelect->addItem("UDP");
    ui->pktSelect->addItem("ICMP");
    ui->pktSelect->addItem("ARP");

    /* 开始抓包按钮 */
    connect(ui->startBtn, &QPushButton::clicked, [=](){
        /* 界面初始化 */
        ui->tcpNum->setText("0");
        ui->udpNum->setText("0");
        ui->httpNum->setText("0");
        ui->icmpNum->setText("0");
        ui->arpNum->setText("0");
        ui->ipv4Num->setText("0");
        ui->ipv6Num->setText("0");
        ui->otherNum->setText("0");
        for(int i =0;i<8;i++)pktCount[i] = 0;
        pktVector.clear();
        pktRaw.clear();
        ui->dataTree->clear();
        ui->dataTable->setRowCount(0);
        ui->pktSelect->setEnabled(false);

        /* 获取网卡名 */
        DevInfo* nic = new DevInfo;
        for (auto nif : nicInfo){
            if(selectedNicName == nif->name){
                nic = nif;
                break;
            }
        }
        capThread = new CapThread(this, nic, ui->pktSelect->currentText());
        capThread->start();

        ui->stopBtn->setEnabled(true);
        ui->startBtn->setEnabled(false);

        /* 抓包，在TableWidget中添加数据 */
        connect(capThread, &CapThread::sendData, ui->dataTable, &DataTable::addData, Qt::QueuedConnection);

        /* 保存QStringList数据 */
        connect(capThread, &CapThread::sendData, this, &MainWindow::saveData, Qt::QueuedConnection);
    });

    /* 结束抓包按钮 */
    connect(ui->stopBtn, &QPushButton::clicked, [=](){
        if(capThread->isRunning()){
            capThread->quit();
            delete capThread;
            capThread = nullptr;
        }

        /* 设置按钮 */
        ui->stopBtn->setEnabled(false);
        ui->startBtn->setEnabled(true);
        ui->pktSelect->setEnabled(true);
        disconnect(capThread);
    });

    /* 返回到网卡选择 */
    connect(ui->backBtn, &QPushButton::clicked, [=](){
        if(capThread != nullptr && capThread->isRunning()){
            capThread->quit();
            delete capThread;
            capThread = nullptr;
            ui->stopBtn->setEnabled(false);
        }
        ui->stackedWidget->setCurrentIndex(NIC_SELECT_SCENE);
        pktVector.clear();
        ui->packetText->clear();
        ui->dataTable->setRowCount(0);
        ui->dataTree->clear();
        ui->tcpNum->setText("0");
        ui->udpNum->setText("0");
        ui->httpNum->setText("0");
        ui->icmpNum->setText("0");
        ui->arpNum->setText("0");
        ui->ipv4Num->setText("0");
        ui->ipv6Num->setText("0");
        ui->otherNum->setText("0");
        ui->stopBtn->setEnabled(false);
        ui->startBtn->setEnabled(true);
        ui->pktSelect->setEnabled(true);
    });

    /* 选中数据包显示详细信息 */
    connect(ui->dataTable, &QTreeWidget::clicked, [=](){
        auto index = ui->dataTable->currentRow();
        ui->dataTree->addPacketInfo(pktVector.at(index));
        ui->packetText->addRawData(pktRaw.at(index)->len, pktRaw.at(index)->pkt_data);
    });
}

MainWindow::~MainWindow()
{
    if(capThread != nullptr && capThread->isRunning()){
        capThread->quit();
        delete capThread;
        capThread = nullptr;
    }
    delete ui;
}

void MainWindow::saveData(QStringList data, uint len, const uchar *pkt_data)
{
    pktVector.push_back(data);
    pktData* rawData = new pktData;
    rawData->len = len;

    /* 拷贝数据 */
    uchar* dataCopy = (uchar *)malloc(sizeof (uchar) * len);
    rawData->pkt_data = dataCopy;
    while(len>0){
        *dataCopy = *pkt_data;
        dataCopy++;
        pkt_data++;
        len--;
    }
    pktRaw.push_back(rawData);
    auto type = *(data.end() - 3);

    if(type == "TCP"){
        pktCount[0]++;pktCount[5]++;
    }else if(type == "UDP"){
        pktCount[1]++;pktCount[5]++;
    }else if(type == "HTTP"){
        pktCount[2]++;pktCount[5]++;
    }else if(type == "ARP"){
        pktCount[4]++;
    }else if(type == "ICMP"){
        pktCount[3]++;pktCount[5]++;
    }else if(type == "IPv4"){
        pktCount[5]++;
    }else if(type == "TCPv6"){
        pktCount[0]++;pktCount[6]++;
    }else if(type == "UDPv6"){
        pktCount[1]++;pktCount[6]++;
    }else if(type == "HTTPv6"){
        pktCount[2]++;pktCount[6]++;
    }else if(type == "ICMPv6"){
        pktCount[3]++;pktCount[6]++;
    }else if(type == "IPv6"){
        pktCount[6]++;
    }else {
        pktCount[7]++;
    }
    ui->tcpNum->setText(QString::number(pktCount[0]));
    ui->udpNum->setText(QString::number(pktCount[1]));
    ui->httpNum->setText(QString::number(pktCount[2]));
    ui->icmpNum->setText(QString::number(pktCount[3]));
    ui->arpNum->setText(QString::number(pktCount[4]));
    ui->ipv4Num->setText(QString::number(pktCount[5]));
    ui->ipv6Num->setText(QString::number(pktCount[6]));
    ui->otherNum->setText(QString::number(pktCount[7]));
}

/* 获取网卡设备列表 */
/* 单独设置文件会报错，因此放在 mainwindown.cpp 中 */
QVector<DevInfo *> MainWindow::getNicInfo()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    QVector<DevInfo *> nicVector;

    /* 获得接口列表 */
    QString str_PCAP_SRC_IF_STRING = PCAP_SRC_IF_STRING;
    QByteArray string_array = str_PCAP_SRC_IF_STRING.toLocal8Bit();
    char* char_PCAP_SRC_IF_STRING = string_array.data();
    if (pcap_findalldevs_ex(char_PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1)
    {
        qDebug("Error in pcap_findalldevs: %s\n",errbuf);
        exit(1);
    }

    /* 扫描列表并打印每一项 */
    for(d=alldevs;d;d=d->next)
    {
        nicVector.append(ifget(d));
    }

    pcap_freealldevs(alldevs);
    return nicVector;
}

/* 获取所有可用信息 */
DevInfo* MainWindow::ifget(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];
    DevInfo * devs = new DevInfo;

    /* 设备名(Name) */
    devs->name = QString(QLatin1String(d->name));

    /* 设备描述(Description) */
    if (d->description)
    {
        devs->description = QString(d->description);
    }

    /* Loopback Address*/
    devs->loopbackAddr = (d->flags & PCAP_IF_LOOPBACK)?"yes":"no";

    /* IP addresses */
    for(a=d->addresses;a;a=a->next) {
        Address * addresses = new Address;
        switch(a->addr->sa_family)
        {
        case AF_INET:
            addresses->saFamily = QString("AF_INET");
            if (a->addr)
            {
                addresses->ipAddr = QString(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            }
            if (a->netmask)
            {
                addresses->netmask = QString(iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            }
            if (a->broadaddr)
            {
                addresses->netmask = QString(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            }
            if (a->dstaddr)
            {
                addresses->netmask = QString(iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            }
            break;

        case AF_INET6:
            addresses->saFamily = QString("AF_INET6");

            if (a->addr)
            {
                addresses->ipAddr = QString(ip6tos(a->addr, ip6str, sizeof(ip6str)));
            }
            break;

        default:
            break;
        }
        devs->ipAddresses.append(addresses);
    }
    return devs;
}


/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char * MainWindow::iptos(u_long in)
//input 为二进制数（十六进制），一共4*8=32位
//直接转为char类型即可，无符号char类型占2个字节，即8位，正好为一个点十进制表示的IP地址的一部分
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = reinterpret_cast<u_char*>(&in);
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* MainWindow::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif


    if(getnameinfo(sockaddr,
                   sockaddrlen,
                   address,
                   static_cast<DWORD>(addrlen),
                   nullptr,
                   0,
                   NI_NUMERICHOST) != 0) address = nullptr;

    return address;
}
