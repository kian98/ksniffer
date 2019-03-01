#ifndef IOSTATS_H
#define IOSTATS_H

#include <QWidget>
#include <QtCharts>
QT_CHARTS_USE_NAMESPACE

namespace Ui {
class IOStats;
}

class IOStats : public QWidget
{
    Q_OBJECT

public:
    explicit IOStats(QWidget *parent = nullptr);
    ~IOStats();
    bool isCustomized = false;

private:
    Ui::IOStats *ui;
    QChart *ioChart;
    QLineSeries *lineSeries;
    QScatterSeries *scatterSeries;
    QLabel *valueLabel;
    void closeEvent(QCloseEvent *event);
    void slotPointHoverd(const QPointF &point, bool state);

    int curTime = 0;
    int curCount = 0;
    int mouseX = 0;
    int mouseY = 0;
protected:
    void wheelEvent(QWheelEvent *event);
public slots:
    void refreshChart(int time, int pCount[]);
    void clearChart();
};

#endif // IOSTATS_H
