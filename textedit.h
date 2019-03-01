#ifndef TEXTEDIT_H
#define TEXTEDIT_H

#include <QPlainTextEdit>

class TextEdit : public QPlainTextEdit
{
    Q_OBJECT
public:
    explicit TextEdit(QWidget *parent = nullptr);

    void addRawData(uint len, const uchar* pkt_data, QStringList data);

signals:

public slots:
};

#endif // TEXTEDIT_H
