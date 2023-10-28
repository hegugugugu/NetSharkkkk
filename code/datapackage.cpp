#include "datapackage.h"
#include <QMetaType>
#include "winsock2.h"
dataPackage::dataPackage()
{
    qRegisterMetaType<dataPackage>("dataPackage");
    this->time = "";
    this->packageType = 0;
    this->lenth = 0;
    this->info = "";
}

void dataPackage::setTime(QString time){
    this->time = time;
}

void dataPackage::setPackageType(int packageType){
    this->packageType = packageType;
}

void dataPackage::setLenth(u_int lenth){
    this->lenth = lenth;
}

void dataPackage::setInfo(QString info){
    this->info = info;
}

void dataPackage::setPointer(const u_char *pkt_content, int size){
    //this->pkt_content = pkt_content;
    //不可以像上面那样写，程序会运行一会就崩溃
    //需要显式申请内存
    this->pkt_content = (u_char*)malloc(size);
    memcpy((char*)(this->pkt_content),pkt_content,size);
}

QString dataPackage::getTime(){
    return this->time;
}

QString dataPackage::getPackageType(){
    //为不同数据包进行编码，不同数据包返回类型不同
    switch (this->packageType) {
    case 1: return "ARP";
    case 2: return "ICMP";
    case 3: return "TCP";
    case 4: return "UDP";
    case 5: return "DNS";
    case 6: return "TLS";
    case 7: return "SSL";
    default: return "";
    }
}

QString dataPackage::getLenth(){
    return QString::number(this->lenth);
}

QString dataPackage::getInfo(){
    return this->info;
}

QString dataPackage::getSource(){
    switch (this->packageType) {
    case 1: return this->getSrcMac();
    default: return this->getSrcIP();
    }
}


QString dataPackage::getDestination(){
    switch (this->packageType) {
    case 1: return this->getDesMac();
    default: return this->getDesIP();
    }
}


QString dataPackage::getSrcMac(){
    ETHER_HEADER*etherNet;
    etherNet = (ETHER_HEADER*)(pkt_content);
    u_char*add = etherNet->etherNetSrcHost;
    if(add){
        QString desMac = byte2string(add,1) + ":"
                + byte2string((add+1),1) + ":"
                + byte2string((add+2),1) + ":"
                + byte2string((add+3),1) + ":"
                + byte2string((add+4),1) + ":"
                + byte2string((add+5),1);
        if(desMac == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(BroadCast)";
        else return desMac;
    }
}

QString dataPackage::getDesMac(){
    ETHER_HEADER*etherNet;
    etherNet = (ETHER_HEADER*)(pkt_content);
    u_char*add = etherNet->etherNetDesHost;
    if(add){
        QString desMac = byte2string(add,1) + ":"
                + byte2string((add+1),1) + ":"
                + byte2string((add+2),1) + ":"
                + byte2string((add+3),1) + ":"
                + byte2string((add+4),1) + ":"
                + byte2string((add+5),1);
        if(desMac == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(BroadCast)";
        else return desMac;
    }
}

QString dataPackage::getDesIP(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    sockaddr_in add;
    add.sin_addr.s_addr = ipNet->desAdd;
    return QString(inet_ntoa(add.sin_addr));
}

QString dataPackage::getSrcIP(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    sockaddr_in add;
    add.sin_addr.s_addr = ipNet->srcAdd;
    return QString(inet_ntoa(add.sin_addr));
}

QString dataPackage::getMacType(){
    ETHER_HEADER*etherNet;
    etherNet = (ETHER_HEADER*)(pkt_content);
    u_short type = ntohs(etherNet->type);
    if(type == 0x0800){//上层封装ipv4
        return "IPV4(0x0800)";
    }
    else if(type == 0x0806){
        return "ARP(0x0806)";
    }
    else{
        return "";
    }
}

/*解析IP*/
QString dataPackage::getIPVersion(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ipNet->versionHesdLenth  >> 4);
}
QString dataPackage::getIPHeadLenth(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    QString res = "";
    int length = ipNet->versionHesdLenth & 0x0F;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length*5) + "bytes (" + QString::number(length) + ")";
    return res;
}
QString dataPackage::getIpTos(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ipNet->TOS));
}
QString dataPackage::getIPTotalLenth(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    return QString::number(ntohs(ipNet->totalLenth));
}
QString dataPackage::getIPIdentification(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    u_char identification = ntohs(ipNet->identification);
    return QString::number(ntohs(ipNet->identification),16);
}
QString dataPackage::getIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->offset)& 0xe000) >> 8,16);
}
/********************** get ip reverse bit **********************/
QString dataPackage::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int bit = (ntohs(ip->offset) & 0x8000) >> 15;
    return QString::number(bit);
}
/********************** get ip DF flag[Don't Fragment] **********************/
QString dataPackage::getIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->offset) & 0x4000) >> 14);
}
/********************** get ip MF flag[More Fragment] **********************/
QString dataPackage::getIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->offset) & 0x2000) >> 13);
}
QString dataPackage::getIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->offset) & 0x1FFF);
}
QString dataPackage::getIPTTL(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    return QString::number(ntohs(ipNet->ttl));
}
QString dataPackage::getIPProtocal(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    int protocol = ipNet->protocal;
        switch (protocol) {
        case 1:return "ICMP (1)";
        case 6:return "TCP (6)";
        case 17:return "UDP (17)";
        default:{
            return "";
        }
    }
}
QString dataPackage::getIPChecksum(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    u_char checksum = ntohs(ipNet->checksum);
    return QString::number(ntohs(ipNet->checksum),16);
}
QString dataPackage::getIPsrcAdd(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ipNet->desAdd;
    return QString(inet_ntoa(srcAddr.sin_addr));
}
QString dataPackage::getIPdesAdd(){
    IP_HEADER*ipNet;
    ipNet = (IP_HEADER*)(pkt_content + 14); //跳过mac部分
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ipNet->desAdd;
    return QString(inet_ntoa(desAddr.sin_addr));
}


/*解析ICMP*/
QString dataPackage::getIcmpType(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->type));
}
/********************** get icmp code **********************/
QString dataPackage::getIcmpCode(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->code));

}
/********************** get icmp checksum **********************/
QString dataPackage::getIcmpCheckSum(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->checksum),16);
}
/********************** get icmp identification **********************/
QString dataPackage::getIcmpIdentification(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->identification));
}
/********************** get icmp sequence **********************/
QString dataPackage::getIcmpSequeue(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->seq));
}
QString dataPackage::getIcmpData(int size){
    char*icmp;
    icmp = (char*)(pkt_content + 14 + 20 + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}

/*解析TCP*/
/********************** get tcp source port **********************/
QString dataPackage::getTcpSourcePort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->srcPort);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp destination port **********************/
QString dataPackage::getTcpDestinationPort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->desPort);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp sequence **********************/
QString dataPackage::getTcpSequence(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->seqNum));
}
/********************** get tcp acknowledgment **********************/
QString dataPackage::getTcpAcknowledgment(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->ackNum));
}
/********************** get tcp header length **********************/
QString dataPackage::getTcpHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int length = (tcp->headLenth >> 4);
    if(length == 5) return "20 bytes (5)";
    else return QString::number(length*4) + " bytes (" + QString::number(length) + ")";
}
QString dataPackage::getTcpRawHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->headLenth >> 4);
}
/********************** get tcp flags **********************/
QString dataPackage::getTcpFlags(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->flags,16);
}
/********************** get tcp PSH **********************/
QString dataPackage::getTcpPSH(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x08) >> 3);
}
/********************** get tcp ACK **********************/
QString dataPackage::getTcpACK(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x10) >> 4);
}
/********************** get tcp SYN **********************/
QString dataPackage::getTcpSYN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x02) >> 1);
}
/********************** get tcp UGR **********************/
QString dataPackage::getTcpURG(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x20) >> 5);
}
/********************** get tcp FIN **********************/
QString dataPackage::getTcpFIN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number((tcp->flags) & 0x01);
}
/********************** get tcp RST **********************/
QString dataPackage::getTcpRST(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x04) >> 2);
}
/********************** get tcp window size **********************/
QString dataPackage::getTcpWindowSize(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->windowSize));
}
/********************** get tcp checksum **********************/
QString dataPackage::getTcpCheckSum(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->checksum),16);
}
/********************** get tcp urgent pointer **********************/
QString dataPackage::getTcpUrgentPointer(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->urgentPointer));
}



QString dataPackage::byte2string(u_char *str, int size){
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
