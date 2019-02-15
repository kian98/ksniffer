#include "datatable.h"
#include <QHeaderView>
#include <QDebug>

DataTable::DataTable(QWidget *parent) : QTableWidget(parent)
{
    /* Header 格式设置 */
    this->horizontalHeader()->setVisible(true);
    this->setColumnCount(6);
    QStringList tableHeader;
    tableHeader << "Time" << "Protocol" << "Source"
                << "Destination" << "Length" << "Info";
    this->setHorizontalHeaderLabels(tableHeader);
    QFont headerFont;
    headerFont.setBold(true);
    this->horizontalHeader()->setFont(headerFont);

    /* 设置整行选中 */
    this->setSelectionBehavior ( QAbstractItemView::SelectRows);
    this->setSelectionMode(QAbstractItemView::SingleSelection);

    /* 设置不可编辑 */
    this->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /* Header 自动填充表 */
    this->horizontalHeader()->setStretchLastSection(true);
}

void DataTable::addData(DataTableItem* data)
{
    int rowIndex = this->rowCount();
    this->insertRow(rowIndex);
    this->setItem(rowIndex, TIME, new QTableWidgetItem(data->timeStamp));
    this->setItem(rowIndex, PROTOCOL, new QTableWidgetItem(ProtName[data->protocol]));
    this->setItem(rowIndex, SOURCE, new QTableWidgetItem(data->source));
    this->setItem(rowIndex, DESTINATION, new QTableWidgetItem(data->dest));
    this->setItem(rowIndex, LENGTH, new QTableWidgetItem(QString::number(data->len)));
    this->setItem(rowIndex, INFO, new QTableWidgetItem(data->info));
}
