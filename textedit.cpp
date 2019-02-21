#include "textedit.h"

TextEdit::TextEdit(QWidget *parent) : QPlainTextEdit(parent)
{
    this->setViewportMargins(5,5,5,5);
}

void TextEdit::addRawData(uint len, const uchar* pkt_data)
{
    this->clear();
    for(uint i = 0;i<len;i++){
        this->insertPlainText(QString("%1 ").arg(pkt_data[i], 2, 16, QLatin1Char('0')));
    }
}
