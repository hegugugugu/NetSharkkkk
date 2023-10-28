#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "datapackage.h"
#include "winsock2.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showNetworkCard();
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);

public slots:
    void haddleMessage(dataPackage data);

private:
    Ui::MainWindow *ui;
    pcap_if_t*allDevice;
    pcap_if_t*device;
    pcap_t*pointer;
    QVector<dataPackage>pData;
    int count;  //数据包个数
    char errorBuff[PCAP_ERRBUF_SIZE]; //错误信息缓冲区
    int selectRow;//选中的一行
};
#endif // MAINWINDOW_H
