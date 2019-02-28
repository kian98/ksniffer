#include "iostats.h"
#include "ui_iostats.h"
#include <numeric>

#include <QDebug>

#define MAX_RANGE 30
#define SCROLL_DIST 30
IOStats::IOStats(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::IOStats)
{
    ui->setupUi(this);

    // 创建平滑曲线上点的序列
    lineSeries = new QLineSeries();
    lineSeries->setName("spline");

    // 创建散列点的序列
    scatterSeries = new QScatterSeries();
    scatterSeries->setMarkerSize(8);

    /* 使用点的序列创建图表 */
    ioChart = ui->ioChartView->chart();
    ioChart->addSeries(lineSeries);
    ioChart->addSeries(scatterSeries);
    ioChart->legend()->hide();

    /* 标题 */
    ioChart->setTitle("KSniffer I/O Stats");
    ioChart->setTitleFont(QFont("Microsoft YaHei", 12, 63));

    /* 坐标轴 */
    //ioChart->createDefaultAxes();
    QValueAxis *axisX = new QValueAxis;
    axisX->setRange(0,MAX_RANGE);
    axisX->setGridLineVisible(true);
    axisX->setTickCount(16);
    axisX->setLabelFormat("%d");
    axisX->setTitleText("Time (Second)");
    ioChart->addAxis(axisX, Qt::AlignBottom);

    QValueAxis *axisY = new QValueAxis;
    axisY->setRange(0,150);
    axisY->setGridLineVisible(true);
    axisY->setTitleText("Packets/Second");
    axisY->setLabelFormat("%d");
    ioChart->addAxis(axisY, Qt::AlignLeft);

    lineSeries->attachAxis(axisX);
    lineSeries->attachAxis(axisY);
    scatterSeries->attachAxis(axisX);
    scatterSeries->attachAxis(axisY);


    /* 曲线抗锯齿 */
    ui->ioChartView->setRenderHint(QPainter::Antialiasing);
}

IOStats::~IOStats()
{
    delete ui;
}

void IOStats::closeEvent(QCloseEvent *event)
{
    this->hide();
}

void IOStats::refreshChart(int time, int pCount[])
{
    int addup = std::accumulate(pCount, pCount+8, 0);
    double rate = (addup - curCount)*1.0 / (time - curTime);
    for(int i = 0; i < time - curTime; i++){
        lineSeries->append(curTime + i, rate);
        scatterSeries->append(curTime + i, rate);
    }
    if(!isCustomized && time > MAX_RANGE){
        ioChart->axes(Qt::Horizontal).back()->setRange(time - MAX_RANGE, time);
    }
    curTime = time;
    curCount = addup;
}

void IOStats::clearChart()
{
    lineSeries->clear();
    scatterSeries->clear();
    curTime = 0;
    curCount = 0;
    ioChart->axes(Qt::Horizontal).back()->setRange(0, MAX_RANGE);
}

void IOStats::wheelEvent(QWheelEvent *event)
{
    QValueAxis *axisX = dynamic_cast<QValueAxis*>(ioChart->axes(Qt::Horizontal).back());
    if(event->delta() > 0){
        qreal scrollLeftDist = axisX->min()>SCROLL_DIST ? SCROLL_DIST : axisX->min();
        if(scrollLeftDist>0){
            ioChart->scroll(-SCROLL_DIST, 0);
            isCustomized = true;
        }
    }else {
        if(axisX->max() + SCROLL_DIST < curTime){
            ioChart->scroll(SCROLL_DIST, 0);
            isCustomized = true;
        }else {
            qreal scrollRightDist = curTime - MAX_RANGE;
            if(scrollRightDist > 0){
                ioChart->scroll(scrollRightDist, 0);
            }
        }
    }
    if(abs(curTime - axisX->max()) < 2){
        isCustomized = false;
    }
}
