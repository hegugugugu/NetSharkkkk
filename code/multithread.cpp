#include "multithread.h"
#include "Format.h"
#include "datapackage.h"
#include <QMainWindow>
#include <QDebug>

multithread::multithread()
{
    this->isDone = true;    //一开始设定为跑完的
}

bool multithread::setPointer(pcap_t*pointer){
    this->pointer = pointer;
    if(pointer){
        return true;
    }
    else{
        return false;
    }
}

void multithread::setFlag(){
    this->isDone = false;
}

void multithread::resetFlag(){
    this->isDone = true;
}

void multithread::run(){
    //不断捕获数据包，循环
    while(true){
        if(isDone){
            break;
        }
        else{
            //pcap_next_ex函数
            int res = pcap_next_ex(pointer,&head,&pktData);
            //我只有两个物理网卡可以抓到包包
            //KPF__{3E3067B6-96BD-425B-BFEB-4C8C13D2F360}Microsoft
            //NPF_ICC815AD2-5AE4-4761-9BCD-75D6300923DD]VMware Virtual Ethernet Adapter
            if(res == 0){
                continue;
            }
            localTimeSec = head->ts.tv_sec; //可以获取时间但不是标准格式
            localtime_s(&localTime,&localTimeSec);
            strftime(timeString,sizeof(timeString),"%H:%M:%S",&localTime);   //输出时间
            qDebug()<<timeString;
            QString info = "";
            int type = etherNetPackageHandle(pktData,info);
            if(type){
                dataPackage data;
                int lenth = head->len;
                data.setInfo(info);
                data.setTime(timeString);
                data.setLenth(lenth);
                data.setPointer(pktData,lenth);
                data.setPackageType(type);
                emit send(data);
            }
        }
    }
}

int multithread::etherNetPackageHandle(const u_char *pkt_content, QString &info){
    ETHER_HEADER*etherNet;
    u_short contentType;
    etherNet = (ETHER_HEADER*)(pkt_content); //强制类型转换
    contentType = ntohs(etherNet->type);    //ntohs进行网络字节流和主机字节流的转换
    switch (contentType) {
    case 0x0800:{//ip
        int ipPackage = 0;
        int res = ipNetPackageHandle(pkt_content,ipPackage);
        switch (res) {
        case 1:{//icmp
            info = 1;
            return 2;
        }
        case 6:{//tcp
            return tcpNetPackageHandle(pkt_content,info,ipPackage);
        }
        case 17:{//udp
            return udpNetPackageHandle(pkt_content,info);
        }
        default: break;
        }
        break;
    }   //IP
    case 0x0806:{
        info = arpNetPackageHandle(pkt_content);
        return 1;
    }  //ARP
    default:break;
    }
    return 0;
}

int multithread::ipNetPackageHandle(const u_char *pkt_content, int &ipPackage){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    int potocal = ipNet->protocal;
    ipPackage = (ntohs(ipNet->totalLenth) - ((ipNet->versionHesdLenth) & 0x0F) * 4);
    return potocal;
}

int multithread::tcpNetPackageHandle(const u_char *pkt_content, QString &info, int ipPackage){
    TCP_HEADER*tcpNet;
    tcpNet = (TCP_HEADER*)(pkt_content + 14 + 20);
    u_short srcPort = ntohs(tcpNet->srcPort);
    u_short desPort = ntohs(tcpNet->desPort);
    QString proSend = "";
    QString proRecv = "";
    int packageType = 3;
    int tcpPackage = ipPackage - (tcpNet->headLenth >> 4) * 4;
    //https,加密过的
    if(srcPort ==443 || desPort == 443){
        if(srcPort == 443){
            proSend = "(https)";
        }
        else{
            proRecv = "(https)";
        }
    }
    //源地址发给目的地址
    info += QString::number(srcPort) + proRecv + "--->" + QString::number(desPort) + proRecv;

    QString flag = "";
    if(tcpNet->flags & 0x20)flag += "URG ";
    if(tcpNet->flags & 0x10)flag += "ACK ";
    if(tcpNet->flags & 0x08)flag += "PSH ";
    if(tcpNet->flags & 0x04)flag += "RST ";
    if(tcpNet->flags & 0x02)flag += "SYN ";
    if(tcpNet->flags & 0x01)flag += "FIN ";
    if(flag != 0){
        flag = flag.left(flag.length() - 1);
        info += "[" + flag + "]";
    }

    u_int seq = ntohs(tcpNet->seqNum);
    u_int ack = ntohs(tcpNet->ackNum);
    u_short windowSize = ntohs(tcpNet->windowSize);
    info += " seq=" + QString::number(seq) + " ack=" + QString::number(ack) + " win=" + QString::number(windowSize) + " len=" + QString::number(tcpPackage);
    return packageType;
}

int multithread::udpNetPackageHandle(const u_char *pkt_content, QString &info){
    UDP_HEADER*udpNet;
    udpNet = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short srcPort = ntohs(udpNet->srcPort);
    u_short desPort = ntohs(udpNet->desPort);
    int packageType;
    if(desPort == 53 || srcPort == 53){
        //DNS
        packageType = 5;
        return packageType;
    }
    else{
        info = QString::number(srcPort) + "--->" + QString::number(desPort);
        u_short len = ntohs(udpNet->dataPackageLenth);
        info += "len=" + QString::number(len);
        packageType = 4;
        return packageType;
    }

}

QString multithread::arpNetPackageHandle(const u_char *pkt_content){
    ARP_HEADER*arpNet;
    arpNet = (ARP_HEADER*)(pkt_content + 14);
    QString info = "";
    u_short op = ntohs(arpNet->opType);
    u_char*desAddr = arpNet->desIp;
    QString desIp = QString::number(*desAddr) + "." + QString::number(*(desAddr+1)) + "." + QString::number(*(desAddr+2)) + "." + QString::number(*(desAddr+3));
    u_char*srcAddr = arpNet->srcIp;
    QString srcIp = QString::number(*srcAddr) + "." + QString::number(*(srcAddr+1)) + "." + QString::number(*(srcAddr+2)) + "." + QString::number(*(srcAddr+3));

    u_char*srcEthAddr = arpNet->srcMac;
    QString srcMac = byte2string(srcEthAddr,1) + ":"
            + byte2string((srcEthAddr+1),1) + ":"
            + byte2string((srcEthAddr+2),1) + ":"
            + byte2string((srcEthAddr+3),1) + ":"
            + byte2string((srcEthAddr+4),1) + ":"
            + byte2string((srcEthAddr+5),1);
    if(op == 1){
        info = "who has " + desIp + " ?Tell " + srcIp;
    }
    else if(op ==2){
        info = srcIp + " is at " + srcMac;
    }
    return info;
}

QString multithread::byte2string(u_char *str, int size){
    QString res = "";
    for(int i = 0; i < size; i++){
        char one = str[i] >> 4;
        if(one >= 0x0A){
            one += 0x41 - 0x0A;
        }
        else{
            one += 0x30;
        }
        char two = str[i] & 0xF;
        if(two >= 0x0A){
            two += 0x41 - 0x0A;
        }
        else{
            two += 0x30;
        }
        res.append(one);
        res.append(two);
    }
    return res;
}






















