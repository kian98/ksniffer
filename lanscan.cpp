#include "lanscan.h"
#include "ui_lanscan.h"
#include <QDialog>
#include <QProgressBar>
#include <cmath>
#include <string.h>
#include <QDebug>

LanScan::LanScan(QWidget *parent, QString nicName, QString nicIP) :
    QWidget(parent),
    ui(new Ui::LanScan)
{
    qRegisterMetaType<QVector<int> >("QVector<int>");
    ui->setupUi(this);
    this->nicName = nicName;
    this->nicIP = nicIP;

    /* 输入框设置 */
    QRegExp ipRx("^((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)$");
    QRegExp muskRx("^([1-2]?\\d|31|32)$");
    ui->ip->setValidator(new QRegExpValidator(ipRx));
    ui->musk->setValidator(new QRegExpValidator(muskRx));
    ui->ip->setText(nicIP);
    ui->musk->setText(QString::number(24));

    /* table 设置 */
    ui->scanTable->horizontalHeader()->setVisible(true);
    ui->scanTable->setColumnCount(2);
    QStringList tableHeader;
    tableHeader << "IP Address" << "MAC Address";
    ui->scanTable->setHorizontalHeaderLabels(tableHeader);
    QFont headerFont;
    headerFont.setBold(true);
    ui->scanTable->horizontalHeader()->setFont(headerFont);
    ui->scanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->scanTable->horizontalHeader()->setStretchLastSection(true);
    ui->scanTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);


    if(! Utils::getNicMAC(nicIP, targetMAC)){
        //
    }

    /* 添加本机信息 */
    int rowIndex = ui->scanTable->rowCount();
    ui->scanTable->insertRow(rowIndex);
    ui->scanTable->setItem(rowIndex, 0, new QTableWidgetItem("(本机)* "+nicIP));
    ui->scanTable->setItem(rowIndex, 1, new QTableWidgetItem(
            QString("%1:%2:%3:%4:%5:%6")
            .arg(targetMAC[0], 2, 16, QLatin1Char('0'))
            .arg(targetMAC[1], 2, 16, QLatin1Char('0'))
            .arg(targetMAC[2], 2, 16, QLatin1Char('0'))
            .arg(targetMAC[3], 2, 16, QLatin1Char('0'))
            .arg(targetMAC[4], 2, 16, QLatin1Char('0'))
            .arg(targetMAC[5], 2, 16, QLatin1Char('0'))));
    ui->scanTable->item(rowIndex, 0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    ui->scanTable->item(rowIndex, 1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);

    connect(ui->scanBtn, &QPushButton::clicked, [=](){
        if(isRunning){
            return;
        }

        if(ui->ip->text().isEmpty()){
            ui->ip->clear();
            ui->ip->setFocus();
        }else if(ui->musk->text().isEmpty()){
            ui->musk->clear();
            ui->musk->setFocus();
        }else {
            ui->scanTable->setRowCount(1);
            auto nicIPlist = nicIP.split(".");
            for(int i = 0;i<4;i++){
                ip_src[i] = static_cast<uchar>(nicIPlist[i].toInt());
            }

            auto ipDestList = ui->ip->text().split(".");
            for(int i = 0; i < 4;i++){
                ip_dest[i] = static_cast<uchar>(ipDestList[i].toInt());
            }

            isRunning = true;
            isInterrupted =false;
            showProgressDialog();

            std::thread t_receive(&LanScan::icmpCapture, this);
            connect(this, &LanScan::addDataRequest, [=](QString info){
                int rowIndex = ui->scanTable->rowCount();

                bool flag = true;
                for(int j = 0;j<rowIndex;j++){
                    if(ui->scanTable->item(j, 1)->text() == info.split(",")[1]){
                        flag = false;
                        break;
                    }
                }
                if(flag){
                    ui->scanTable->insertRow(rowIndex);
                    ui->scanTable->setItem(rowIndex, 0, new QTableWidgetItem(info.split(",")[0]));
                    ui->scanTable->setItem(rowIndex, 1, new QTableWidgetItem(info.split(",")[1]));
                    ui->scanTable->item(rowIndex, 0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                    ui->scanTable->item(rowIndex, 1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                }
            });
            t_receive.detach();
            std::thread t_request(&LanScan::icmpRequest, this,
                                  targetMAC, ip_src, ip_dest, ui->musk->text().toInt());
            connect(this, &LanScan::interrupt, [=](){
                isInterrupted = true;
            });
            t_request.detach();
        }
    });
}

LanScan::~LanScan()
{
    delete ui;
}

void LanScan::closeEvent(QCloseEvent *event)
{
    emit beClosed();
}


void LanScan::icmpRequest(u_char mac_src[6], u_char ip_src[4], u_char ip_dest[4], int musk)
{
    /* 等待接受线程开启 */
    Sleep(50);

    char errbuf[PCAP_ERRBUF_SIZE];
    u_long jobCount = static_cast<u_long>(pow(2, 32-musk));
    u_char packet[42];
    u_long *ipStart;

    u_char mac_dest[6];
    memset(mac_dest, 0xff,6);

    /* 由于ulong对字节读取顺序不同，因此遍历ip地址需要特殊处理 */
    u_char ip_invert[4];
    for(int i = 0;i<4;i++){
        ip_invert[i] = ip_dest[3-i];
    }

    ipStart = (u_long*)ip_invert;
    *ipStart =((*ipStart)>>(32-musk))<<(32-musk);

    if ((fp= pcap_open(this->nicName.toLocal8Bit().data(),          // 设备名
                       65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                       PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                       1000,             // 读取超时时间
                       nullptr,             // 远程机器验证
                       errbuf            // 错误缓冲池
                       )) == nullptr)
    {
        //        emit sendText("Error when open the adapter.");
    }

    for(u_long i =0; i< jobCount; i++){
        u_long ip_increase = (*ipStart) | i;
        ip_dest = (u_char*)&ip_increase;
        std::swap(ip_dest[0], ip_dest[3]);
        std::swap(ip_dest[1], ip_dest[2]);
        if(!Utils::IcmpGenerator(mac_src, ip_src, mac_dest, ip_dest, packet)){

        }
        if (pcap_sendpacket(fp, packet, 42 /* size */) != 0)
        {
            //            emit sendText("Error sending the ICMP packet.");
        }
    }
    pcap_close(fp);
    Sleep(1000);
    emit interrupt();
}

void LanScan::icmpCapture()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
    int res = 0;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    const char *packet_filter;

    packet_filter = "icmp";

    if ( (adhandle= pcap_open(nicName.toLocal8Bit().data(),  // 设备名
                              65536,     // 要捕捉的数据包的部分
                              // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
                              1000,      // 读取超时时间
                              nullptr,      // 远程机器验证
                              errbuf     // 错误缓冲池
                              ) ) == nullptr)
    {
        //emit sendWaningMsg("Not Supported", "Unable to open the adapter.");
    }

    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        //emit sendWaningMsg("Ethernet Only", "This program works only on Ethernet networks.");
    }

    u_int netmask=0xffffff;

    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        //emit sendWaningMsg("Compile Error", "Unable to compile the packet filter. Start without filter.");
    }else if (pcap_setfilter(adhandle, &fcode)<0)
    {
        //emit sendWaningMsg("Filter Error", "Error setting the filter.");
    }

    while(!isInterrupted &&(res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

        if(res == 0)
            /* 超时时间到 */
            continue;
        auto info = icmpAnalysis(pkt_data);
        if(!info.isEmpty()){
            emit addDataRequest(info.join(","));
        }
    }

    if(res == -1){
        //emit sendWaningMsg("Error", QString("Error reading the packets: %1.").arg(pcap_geterr(adhandle)));
    }

    pcap_close(adhandle);
    isRunning = false;
    emit scanFinish();
}

QStringList LanScan::icmpAnalysis(const u_char *pkt_data)
{
    eth_header *eth;
    ip_header *ipv4;
    icmp_header *icmp;
    QStringList info;

    eth = (eth_header *)pkt_data;
    eth->type = ntohs(eth->type);

    if(eth->type == 0x0800){
        ipv4 = (ip_header *)(pkt_data + IP_HEADER_OFFSET);
        if(ipv4->proto == 1){
            icmp = (icmp_header *)(pkt_data + (IP_HEADER_OFFSET + ipv4->ihl*4));
            if(icmp->type == 0){
                info << QString("%1.%2.%3.%4")
                        .arg(ipv4->saddr[0]).arg(ipv4->saddr[1])
                        .arg(ipv4->saddr[2]).arg(ipv4->saddr[3]);
                info << QString("%1:%2:%3:%4:%5:%6")
                        .arg(eth->src[0], 2, 16, QLatin1Char('0'))
                        .arg(eth->src[1], 2, 16, QLatin1Char('0'))
                        .arg(eth->src[2], 2, 16, QLatin1Char('0'))
                        .arg(eth->src[3], 2, 16, QLatin1Char('0'))
                        .arg(eth->src[4], 2, 16, QLatin1Char('0'))
                        .arg(eth->src[5], 2, 16, QLatin1Char('0'));
            }
        }
    }
    return info;
}

void LanScan::showProgressDialog()
{
    QDialog *progressDlg = new QDialog(this, Qt::WindowCloseButtonHint);
    progressDlg->setWindowTitle("Scanning");
    progressDlg->setModal(true);
    progressDlg->setFixedSize(300,50);

    QVBoxLayout *layout = new QVBoxLayout(progressDlg);
    QProgressBar *progBar = new QProgressBar(progressDlg);
    progBar->setAlignment(Qt::AlignCenter);
    progBar->setMinimum(0);progBar->setMaximum(0);
    layout->addWidget(progBar);
    progressDlg->show();
    connect(this, &LanScan::scanFinish, [=](){
        progressDlg->close();
    });
}
