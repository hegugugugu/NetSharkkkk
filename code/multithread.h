#ifndef MULTITHREAD_H
#define MULTITHREAD_H
#include <QMainWindow>
#include "pcap.h"
#include "datapackage.h"
#include "QThread"

//多线程继承thread
class multithread:public QThread
{
    //需要添加信号和槽
    Q_OBJECT
public:
    multithread();
    void run() override;
    bool setPointer(pcap_t*pointer);
    void setFlag();   //控制开关变量
    void resetFlag();
    int etherNetPackageHandle(const u_char*pkt_content,QString&info); //从mac层开始解析数据
    int ipNetPackageHandle(const u_char*pkt_content,int&ipPackage);
    int tcpNetPackageHandle(const u_char*pkt_content,QString&info,int ipPackage);
    int udpNetPackageHandle(const u_char*pkt_content,QString&info); //udp有一个字段是数据长度，不需要算delta
    QString arpNetPackageHandle(const u_char*pkt_content);
protected:
    static QString byte2string(u_char*str,int size); //将一个字节转化为16进制

signals:
    void send(dataPackage data);


private:
    pcap_t*pointer;
    struct pcap_pkthdr*head;    //数据包头部的结构
    const u_char*pktData;
    time_t localTimeSec;
    struct tm localTime;
    char timeString[16];   //时间戳
    bool isDone;
};

#endif // MULTITHREAD_H
