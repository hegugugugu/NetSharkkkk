#ifndef FORMAT_H
#define FORMAT_H

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

typedef struct etherHeader{
    u_char etherNetDesHost[6];
    u_char etherNetSrcHost[6];
    u_short type;
}ETHER_HEADER;

typedef struct ipHeader{
    u_char versionHesdLenth;
    u_char TOS;
    u_short totalLenth;
    u_short identification;
    u_short offset;
    u_char ttl;
    u_char protocal;
    u_short checksum;
    u_int srcAdd;
    u_int desAdd;
}IP_HEADER;

typedef struct tcpHeader{
    u_short srcPort;
    u_short desPort;
    u_int seqNum;
    u_int ackNum;
    u_char headLenth;
    u_char flags;
    u_short windowSize;
    u_short checksum;
    u_short urgentPointer;
}TCP_HEADER;

typedef struct udpHeader{
    u_short srcPort;
    u_short desPort;
    u_short dataPackageLenth;
    u_short checksum;
}UDP_HEADER;

typedef struct arpHeader{
    u_short type;
    u_short protocal;
    u_char macLenth;
    u_char ipLenth;
    u_short opType;
    u_char srcMac[6];
    u_char srcIp[4];
    u_char desMac[6];
    u_char desIp[4];
}ARP_HEADER;

typedef struct icmpHeader{
    u_short type;
    u_short code;
    u_short checksum;
    u_short identification;
    u_short seq;
}ICMP_HEADER;

#endif // FORMAT_H
