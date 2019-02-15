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
        ui->nicName->setText(curNicName[1]);
    });

    /* 取消选择，退出 */
    connect(ui->nicCancel, &QPushButton::clicked, [=](){
        this->close();
    });

    /******** 数据监听界面 ********/
    /* 设置按钮 Enabled */
    ui->stopBtn->setEnabled(false);

    /* 开始抓包按钮 */
    connect(ui->startBtn, &QPushButton::clicked, [=](){
        DevInfo* nic = new DevInfo;
        for (auto nif : nicInfo){
            if(ui->nicName->text() == nif->name){
                nic = nif;
                break;
            }
        }
        capThread = new CapThread(nic);
        capThread->start();
        ui->stopBtn->setEnabled(true);
        ui->startBtn->setEnabled(false);

        /* 抓包，在TableWidget中添加数据 */
        ui->dataTable->setRowCount(0);
        connect(capThread, &CapThread::sendTableData, ui->dataTable, &DataTable::addData, Qt::QueuedConnection);

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
        disconnect(capThread);
        qDebug("Stop");
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
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

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
    //qDebug("%s",d->name);
    devs->name = QString(QLatin1String(d->name));

    /* 设备描述(Description) */
    if (d->description)
    {
        devs->description = QString(d->description);
        //qDebug("\tDescription: %s",d->description);
    }

    /* Loopback Address*/
    devs->loopbackAddr = (d->flags & PCAP_IF_LOOPBACK)?"yes":"no";
    //qDebug("\tLoopback: %s",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

    /* IP addresses */
    for(a=d->addresses;a;a=a->next) {
        //qDebug("\tAddress Family: #%d",a->addr->sa_family);
        Address * addresses = new Address;
        switch(a->addr->sa_family)
        {
        case AF_INET:
            //qDebug("\tAddress Family Name: AF_INET");
            addresses->saFamily = QString("AF_INET");
            if (a->addr)
            {
                addresses->ipAddr = QString(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                //qDebug("\tAddress: %s",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            }
            if (a->netmask)
            {
                addresses->netmask = QString(iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                //qDebug("\tNetmask: %s",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            }
            if (a->broadaddr)
            {
                addresses->netmask = QString(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                //qDebug("\tBroadcast Address: %s",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            }
            if (a->dstaddr)
            {
                addresses->netmask = QString(iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                //qDebug("\tDestination Address: %s",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            }
            break;

        case AF_INET6:
            //qDebug("\tAddress Family Name: AF_INET6");
            addresses->saFamily = QString("AF_INET6");

            if (a->addr)
            {
                addresses->ipAddr = QString(ip6tos(a->addr, ip6str, sizeof(ip6str)));
                //qDebug("\tAddress: %s", ip6tos(a->addr, ip6str, sizeof(ip6str)));
            }
            break;

        default:
            //qDebug("\tAddress Family Name: Unknown");
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
