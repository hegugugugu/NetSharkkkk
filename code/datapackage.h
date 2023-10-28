#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include "Format.h"
#include <QString>

class dataPackage
{
private:
    //仿照wireshark页面,packetList
    QString time;   //时间戳
    u_int lenth;    //长度
    int packageType;    //数据包类型
    QString info;   //其他信息
protected:
    static QString byte2string(u_char*str,int size); //将一个字节转化为16进制
public:
    const u_char*pkt_content;   //用于显示packetDtail
public:
    dataPackage();

    void setTime(QString time);
    void setLenth(u_int lenth);
    void setPackageType(int packageType);
    void setInfo(QString info);
    void setPointer(const u_char*pkt_content,int size);

    QString getTime();
    QString getLenth();
    QString getPackageType();
    QString getInfo();
    QString getSource();
    QString getDestination();

    QString getDesMac();
    QString getSrcMac();
    QString getMacType();//上层封装的协议

    QString getDesIP();
    QString getSrcIP();

    QString getIPVersion();//IP上层封装的协议
    QString getIPHeadLenth();
    QString getIpTos();
    QString getIPTotalLenth();
    QString getIPIdentification();
    QString getIpFlag();
    QString getIpReservedBit();
    QString getIpDF();
    QString getIpMF();
    QString getIpFragmentOffset();
    QString getIPTTL();
    QString getIPProtocal();
    QString getIPChecksum();
    QString getIPsrcAdd();
    QString getIPdesAdd();

    QString getIcmpType();//icmp上层封装的协议
    QString getIcmpCode();
    QString getIcmpCheckSum();
    QString getIcmpIdentification();
    QString getIcmpSequeue();
    QString getIcmpData(int size);

    // get the tcp info
    QString getTcpSourcePort();               // get tcp source port
    QString getTcpDestinationPort();          // get tcp destination port
    QString getTcpSequence();                 // get tcp sequence
    QString getTcpAcknowledgment();           // get acknowlegment
    QString getTcpHeaderLength();             // get tcp head length
    QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    QString getTcpFlags();                    // get tcp flags
    QString getTcpPSH();                      // PSH flag
    QString getTcpACK();                      // ACK flag
    QString getTcpSYN();                      // SYN flag
    QString getTcpURG();                      // URG flag
    QString getTcpFIN();                      // FIN flag
    QString getTcpRST();                      // RST flag
    QString getTcpWindowSize();               // get tcp window size
    QString getTcpCheckSum();                 // get tcp checksum
    QString getTcpUrgentPointer();            // get tcp urgent pointer
    QString getTcpOperationKind(int kind);    // get tcp option kind
    int getTcpOperationRawKind(int offset);   // get tcp raw option kind
};

#endif // DATAPACKAGE_H
