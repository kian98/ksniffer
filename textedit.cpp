#include "textedit.h"

TextEdit::TextEdit(QWidget *parent) : QPlainTextEdit(parent)
{
    this->setViewportMargins(5,5,5,5);
    this->setReadOnly(true);
}

void TextEdit::addRawData(uint len, const uchar* pkt_data, QStringList data)
{
    this->clear();
    QString more = "";
    if(len > 350) {
        len = 350;
        more = "···(.etc)";
    }
    for(uint i = 0;i<len;i++){
        this->insertPlainText(QString("%1 ").arg(pkt_data[i], 2, 16, QLatin1Char('0')));
    }
    this->insertPlainText(more);
    if(*(data.end()-5) == "Type: GET" || *(data.end()-5) == "Type: POST"){
        this->insertPlainText("\n\nHTTP CONTENT:\n");
        this->insertPlainText(*(data.end()-4));
    }
}
