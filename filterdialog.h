#ifndef FILTERDIALOG_H
#define FILTERDIALOG_H

#include <QDialog>

namespace Ui {
class FilterDialog;
}

class FilterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FilterDialog(QWidget *parent = nullptr);
    ~FilterDialog();

private:
    Ui::FilterDialog *ui;

    void showAddDialog(int index);
    QString filterSyntax(QStringList fList);

signals:
    void sendCustomFilter(QString f);
};

#endif // FILTERDIALOG_H
