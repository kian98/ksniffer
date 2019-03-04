#include "filterdialog.h"
#include "ui_filterdialog.h"
#include <QLineEdit>
#include <QGroupBox>
#include <QCheckBox>

#include <QDebug>

FilterDialog::FilterDialog(QWidget *parent) :
    QDialog(parent, Qt::WindowCloseButtonHint),
    ui(new Ui::FilterDialog)
{
    ui->setupUi(this);

    /* 设置下拉框 */
    ui->filterType->setView(new QListView);
    QStringList filters;
    filters << "Protocol" << "MAC Address" << "IP Address" << "Port";
    ui->filterType->addItems(filters);
    ui->filterType->setCurrentIndex(0);

    /* 设置Add按钮 */
    connect(ui->addBtn, &QPushButton::clicked, [=](){
        showAddDialog(ui->filterType->currentIndex());
    });

    /* 设置Del按钮 */
    ui->delBtn->setEnabled(false);
    connect(ui->filterList, &QListWidget::itemClicked, [=](){
        ui->delBtn->setEnabled(true);
    });
    connect(ui->delBtn, &QPushButton::clicked, [=](){
        int itemIndex = ui->filterList->currentRow();
        ui->filterList->takeItem(itemIndex);
        ui->delBtn->setEnabled(false);
    });

    /* 设置确认按钮 */
    connect(ui->buttonBox, &QDialogButtonBox::accepted, [=](){
        QStringList allSentences;
        for(int i = 0;i<ui->filterList->count();i++){
            allSentences << ui->filterList->item(i)->text();
        }
        emit sendCustomFilter(filterSyntax(allSentences));
    });
}

FilterDialog::~FilterDialog()
{
    delete ui;
}

void FilterDialog::showAddDialog(int index)
{
    QDialog *addDialog = new QDialog(this, Qt::WindowCloseButtonHint);
    addDialog->setModal(true);
    addDialog->setMinimumSize(300, 140);

    QVBoxLayout *layout = new QVBoxLayout;
    QLineEdit *input = new QLineEdit();
    input->resize(250, 28);
    QDialogButtonBox *dlgBtnBox = new QDialogButtonBox(QDialogButtonBox::Ok);

    switch(index){
    case 0:
        addDialog->setWindowTitle("Add Protocol");
        input->setPlaceholderText("Input Correct Format !");
        layout->addWidget(input);
        layout->addWidget(dlgBtnBox);
        addDialog->setLayout(layout);
        addDialog->show();

        connect(dlgBtnBox, &QDialogButtonBox::accepted, [=](){
            if(!input->text().isEmpty()){
                ui->filterList->addItem("Proto: " + input->text().toLower());
                addDialog->close();
            }
        });

        break;
    case 1:
    {
        addDialog->setWindowTitle("Add MAC Address");
        input->setPlaceholderText("Input MAC Address");
        QRegExp macRx("([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})");
        QRegExpValidator* macValidator = new QRegExpValidator(macRx);
        input->setValidator(macValidator);

        QGroupBox *macGroup = new QGroupBox; QHBoxLayout *macGroupLayout = new QHBoxLayout;
        macGroup->setLayout(macGroupLayout);
        QCheckBox *srcMACCheck = new QCheckBox; QCheckBox *destMACCheck = new QCheckBox;
        macGroupLayout->addWidget(srcMACCheck); macGroupLayout->addWidget(destMACCheck);
        srcMACCheck->setText("Source"); destMACCheck->setText("Destination");
        srcMACCheck->setChecked(true); destMACCheck->setChecked(true);

        layout->addWidget(macGroup); layout->addWidget(input);
        layout->addWidget(dlgBtnBox); addDialog->setLayout(layout);
        addDialog->show();

        connect(srcMACCheck, &QCheckBox::stateChanged, [=](int state){
            if(!state && !destMACCheck->isChecked()){destMACCheck->setChecked(true);}});
        connect(destMACCheck, &QCheckBox::stateChanged, [=](int state){
            if(!state && !srcMACCheck->isChecked()){srcMACCheck->setChecked(true);}});

        connect(dlgBtnBox, &QDialogButtonBox::accepted, [=](){
            if(input->text().size() < 7){
                input->clear();
                input->setPlaceholderText("Wrong Input");
            }else {
                QString ipState = srcMACCheck->isChecked()?
                            (destMACCheck->isChecked() ? "ether host " : "ether src ") :
                            (destMACCheck->isChecked() ? "ether dst " : "ether host ");
                ui->filterList->addItem("MAC: " + ipState + input->text());
                addDialog->close();
            }
        });
        break;
    }
    case 2:
    {
        addDialog->setWindowTitle("Add IP Address");
        input->setPlaceholderText("Input IP Address");
        QRegExp ipRx("^((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)$");
        QRegExpValidator* IPValidator = new QRegExpValidator(ipRx);
        input->setValidator(IPValidator);

        QGroupBox *ipGroup = new QGroupBox; QHBoxLayout *ipGroupLayout = new QHBoxLayout;
        ipGroup->setLayout(ipGroupLayout);
        QCheckBox *srcCheck = new QCheckBox; QCheckBox *destCheck = new QCheckBox;
        ipGroupLayout->addWidget(srcCheck); ipGroupLayout->addWidget(destCheck);
        srcCheck->setText("Source"); destCheck->setText("Destination");
        srcCheck->setChecked(true); destCheck->setChecked(true);

        layout->addWidget(ipGroup); layout->addWidget(input);
        layout->addWidget(dlgBtnBox); addDialog->setLayout(layout);
        addDialog->show();

        connect(srcCheck, &QCheckBox::stateChanged, [=](int state){
            if(!state && !destCheck->isChecked()){destCheck->setChecked(true);}});
        connect(destCheck, &QCheckBox::stateChanged, [=](int state){
            if(!state && !srcCheck->isChecked()){srcCheck->setChecked(true);}});

        connect(dlgBtnBox, &QDialogButtonBox::accepted, [=](){
            if(input->text().size() < 7){
                input->clear();
                input->setPlaceholderText("Wrong Input");
            }else {
                QString ipState = srcCheck->isChecked()?
                            (destCheck->isChecked() ? "host " : "src host ") :
                            (destCheck->isChecked() ? "dst host " : "host ");
                ui->filterList->addItem("IP: " + ipState + input->text());
                addDialog->close();
            }
        });
        break;
    }
    case 3:
    {
        QRegExp numRx("(^[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]{1}|6553[0-5]$ )");
        QRegExpValidator* numValidator = new QRegExpValidator(numRx);
        input->setValidator(numValidator);
        addDialog->setWindowTitle("Add Port");
        input->setPlaceholderText("Input Port (1 ~ 65535)");
        layout->addWidget(input);
        layout->addWidget(dlgBtnBox);
        addDialog->setLayout(layout);
        addDialog->show();

        connect(dlgBtnBox, &QDialogButtonBox::accepted, [=](){
            if(!input->text().isEmpty()){
                ui->filterList->addItem("Port: port " + input->text());
                addDialog->close();
            }
        });
        break;
    }
    };
}

QString FilterDialog::filterSyntax(QStringList fList)
{
    QStringList proto;
    QStringList ip;
    QStringList mac;
    QStringList port;
    for(auto str : fList){
        QString type = str.split(": ")[0];
        QString content = str.split(": ")[1];
        if(type == "Proto"){
            proto << content;
        }else if(type == "MAC"){
            mac << content;
        }else if(type == "IP"){
            ip << content;
        }else if(type == "Port"){
            port<< content;
        }
    }
    QStringList all;
    if(!proto.isEmpty()){
        all << "("+proto.join(" or ")+")";
    }
    if(!ip.isEmpty()){
        all << "("+ip.join(" or ")+")";
    }
    if(!mac.isEmpty()){
        all << "("+mac.join(" or ")+")";
    }
    if(!port.isEmpty()){
        all << "("+port.join(" or ")+")";
    }
    return all.join(" and ");
}
